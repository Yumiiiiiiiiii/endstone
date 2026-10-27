"""Compare BDS ELF evidence; candidates never update hooks or certify native ABI."""
from __future__ import annotations

import argparse
import bisect
import difflib
import hashlib
import io
import json
import re
import struct
import tomllib
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
DISASM = Cs(CS_ARCH_X86, CS_MODE_64)


class Binary:
    def __init__(self, archive: Path):
        self.archive_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
        with ZipFile(archive) as zipped:
            self.raw = zipped.read('bedrock_server')
        self.sha256 = hashlib.sha256(self.raw).hexdigest()
        elf = ELFFile(io.BytesIO(self.raw))
        if elf.elfclass != 64 or elf['e_machine'] != 'EM_X86_64':
            raise ValueError('Expected a Linux x86-64 BDS ELF')
        self.sections = [(s['sh_offset'], s['sh_size'], s['sh_addr']) for s in elf.iter_sections()
                         if s['sh_type'] != 'SHT_NOBITS' and s['sh_flags'] & 2]
        text = elf.get_section_by_name('.text')
        self.text = text.data()
        self.base = text['sh_addr']
        header = elf.get_section_by_name('.eh_frame_hdr')
        data = header.data()
        if data[:4] != b'\x01\x1b\x03\x3b':
            raise ValueError(f'Unsupported unwind header encoding: {data[:4].hex()}')
        count = struct.unpack_from('<I', data, 8)[0]
        end = 12 + count * 8
        if len(data) < end or len(data) - end > 15 or any(data[end:]):
            raise ValueError(f'Unwind index length mismatch: length={len(data)} count={count} prefix={data[:24].hex()}')
        self.functions = {}
        self.unwind_rejected = 0
        for start, fde in struct.iter_unpack('<ii', data[12:end]):
            start += header['sh_addr']
            fde += header['sh_addr']
            offset = self.file_offset(fde)
            if offset is None:
                self.unwind_rejected += 1
                continue
            initial, size = struct.unpack_from('<iI', self.raw, offset + 8)
            if fde + 8 + initial != start or not 0 < size <= len(self.text):
                self.unwind_rejected += 1
                continue
            self.functions[start] = size
        self.starts = sorted(self.functions)
        self.relocations = {}
        self.references = defaultdict(list)
        relocation = elf.get_section_by_name('.rela.dyn')
        for offset, info, addend in struct.iter_unpack('<QQq', relocation.data()):
            if info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
                self.relocations[offset] = addend
                self.references[addend].append(offset)
        self.leas = defaultdict(list)
        self.lea_targets = {}
        for match in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....', self.text, re.DOTALL):
            address = self.base + match.start()
            target = address + 7 + struct.unpack_from('<i', self.text, match.start() + 3)[0]
            self.leas[target].append(address)
            self.lea_targets[address] = target
        self.fingerprints = {}
        self.labels_cache = {}
        self.label_functions_cache = {}
        self.calls_cache = {}

    def file_offset(self, address):
        for offset, size, base in self.sections:
            if base <= address < base + size:
                return offset + address - base
        return None

    def address(self, offset):
        for start, size, base in self.sections:
            if start <= offset < start + size:
                return base + offset - start
        return None

    def pointer(self, address):
        if address in self.relocations:
            return self.relocations[address]
        offset = self.file_offset(address)
        return struct.unpack_from('<Q', self.raw, offset)[0] if offset is not None else 0

    def string_at(self, address):
        offset = self.file_offset(address)
        if offset is None:
            return None
        end = self.raw.find(b'\0', offset, offset + 2000)
        if end < offset + 5:
            return None
        raw = self.raw[offset:end]
        if any(byte < 32 or byte > 126 for byte in raw):
            return None
        return raw.decode('ascii')

    def instructions(self, address):
        start = self.containing(address)
        if start is None:
            return
        size = min(self.functions[start], 200000)
        yield from DISASM.disasm(self.text[start - self.base:start - self.base + size], start)

    def calls(self, address):
        if address not in self.calls_cache:
            result = set()
            for instruction in self.instructions(address):
                if instruction.mnemonic == 'call' and instruction.op_str.startswith('0x'):
                    target = int(instruction.op_str, 16)
                    if target in self.functions:
                        result.add(target)
            self.calls_cache[address] = result
        return self.calls_cache[address]

    def labels(self, address):
        if address not in self.labels_cache:
            result = set()
            for instruction in self.instructions(address):
                if instruction.mnemonic != 'lea' or instruction.address not in self.lea_targets:
                    continue
                target = self.lea_targets[instruction.address]
                text = self.string_at(target)
                if text and len(text) >= 8:
                    result.add(('string', text))
                    continue
                typeinfo = self.pointer(target - 8)
                typename = self.string_at(self.pointer(typeinfo + 8))
                if typename and (typename[:1].isdigit() or typename.startswith('N')):
                    result.add(('rtti', typename))
            self.labels_cache[address] = result
        return self.labels_cache[address]

    def functions_for_label(self, label):
        if label not in self.label_functions_cache:
            kind, text = label
            if kind == 'string':
                result = self.string_functions(text)
            else:
                result = set()
                for table in self.tables_for_encoded(text.encode() + b'\0'):
                    for address in self.leas.get(table['address'], []):
                        start = self.containing(address)
                        if start is not None:
                            result.add(start)
            self.label_functions_cache[label] = result
        return self.label_functions_cache[label]

    def containing(self, address):
        index = bisect.bisect_right(self.starts, address) - 1
        if index < 0:
            return None
        start = self.starts[index]
        return start if address < start + self.functions[start] else None

    def fingerprint(self, address):
        if address not in self.fingerprints:
            start = self.containing(address)
            if start is None:
                return []
            size = min(self.functions[start], 16000)
            code = self.text[start - self.base:start - self.base + size]
            result = []
            for index, instruction in enumerate(DISASM.disasm(code, start)):
                if index == 1200:
                    break
                operands = instruction.op_str
                # Keep indirect-call displacements: [vptr+0xNN] is an ABI slot,
                # not a link-time address that may be normalized away.
                if instruction.mnemonic.startswith(('j', 'call')) and operands.startswith('0x'):
                    operands = re.sub(r'0x[0-9a-f]+', '<target>', operands)
                operands = re.sub(r'rip [+-] 0x[0-9a-f]+', 'rip <target>', operands)
                result.append(instruction.mnemonic + ' ' + operands)
            self.fingerprints[address] = result
        return self.fingerprints[address]

    def string_functions(self, text):
        targets = []
        position = 0
        while (position := self.raw.find(text.encode() + b'\0', position)) >= 0:
            address = self.address(position)
            if address is not None:
                targets.extend(self.leas.get(address, []))
            position += 1
        # A byte-shaped LEA inside another instruction is not an xref. Confirm
        # its boundary in the FDE's actual disassembly before keeping it.
        functions = set()
        for address in targets:
            start = self.containing(address)
            if start is None:
                continue
            prefix = self.text[start - self.base:address - self.base + 7]
            if any(i.address == address and i.mnemonic == 'lea' for i in DISASM.disasm(prefix, start)):
                functions.add(start)
        return sorted(functions)

    def vtables(self, class_name):
        encoded = f'{len(class_name)}{class_name}'.encode() + b'\0'
        return self.tables_for_encoded(encoded)

    def type_names_containing(self, fragment):
        names = set()
        position = 0
        while (position := self.raw.find(fragment.encode(), position)) >= 0:
            start = self.raw.rfind(b'\0', max(0, position - 2000), position) + 1
            end = self.raw.find(b'\0', position, position + 2000)
            position += len(fragment)
            if end < start:
                continue
            raw = self.raw[start:end]
            if raw and len(raw) < 4000 and all(32 <= b <= 126 for b in raw):
                name = raw.decode('ascii')
                if name[0].isdigit() or name.startswith(('N', 'Z')):
                    names.add(name)
        return sorted(names)

    def thunk_target(self, address):
        if self.functions.get(address, 1000) <= 32:
            for instruction in self.instructions(address):
                if instruction.mnemonic == 'jmp' and instruction.op_str.startswith('0x'):
                    target = int(instruction.op_str, 16)
                    if target in self.functions:
                        return target
        return address

    def tables_for_encoded(self, encoded, primary_only=True):
        tables = []
        position = 0
        while (position := self.raw.find(encoded, position)) >= 0:
            address = self.address(position)
            position += 1
            for name_pointer in self.references.get(address, []):
                typeinfo = name_pointer - 8
                for slot in self.references.get(typeinfo, []):
                    top = self.pointer(slot - 8)
                    if top & (1 << 63):
                        top -= 1 << 64
                    if (primary_only and top != 0) or not -100000 <= top <= 0:
                        continue
                    table = []
                    for index in range(1200):
                        target = self.pointer(slot + 8 + index * 8)
                        if not self.base <= target < self.base + len(self.text):
                            break
                        table.append(target)
                    if table:
                        tables.append({'address': slot + 8, 'offset_to_top': top, 'slots': table})
        return tables

    def scan(self, signature):
        pattern = b''.join(b'.' if part == '?' else re.escape(bytes.fromhex(part))
                           for part in signature['pattern'].split())
        result = set()
        for match in re.finditer(pattern, self.text, re.DOTALL):
            address = match.start()
            for offset in signature.get('offsets', []):
                address = struct.unpack_from('<I', self.text, address + offset)[0]
            if signature.get('rip_relative'):
                address += signature.get('rip_offset', 0)
                address += struct.unpack_from('<i', self.text, address)[0] + 4
            address += signature.get('extra', 0)
            if not signature.get('relative'):
                address += self.base
            result.add(address)
        return sorted(result)


STRINGS = {
    '_ZN15BlockDescriptor13ResolveHelper7resolveEb': ['No block descriptor to resolve during deferred resolution'],
    '_ZN14ServerInstance16initializeServerEO27ServerInstanceInitArguments': ['Experiment(s) active: '],
    '_ZN20ServerNetworkHandler15tryToLoadPlayerER12ServerPlayerRK17ConnectionRequestRK24PlayerAuthenticationInfo': ['minecraft:player.0'],
    '_ZN20ServerNetworkHandler20_validateLoginPacketERK17NetworkIdentifierRK11LoginPacket': ['realms'],
    '_ZN13NetworkSystem4sendERK17NetworkIdentifierRK6Packet11SubClientId': ['Header Data'],
    '_ZN10LevelChunk8tickImplER11BlockSourceRK4TickNSt3__18functionIFvvEEE': [],
    '_ZN10SayCommand12_sendMessageERKNSt3__112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEERKNS0_8optionalIS6_EES8_RK21CommandOriginIdentityR5Level': ['chat.type.announcement'],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--target-version', default='1.26.60')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'1\.\d+\.\d+', args.target_version):
        parser.error('Use a BDS version such as 1.26.60')
    old = Binary(args.baseline)
    new = Binary(args.target)
    config = tomllib.loads((ROOT / 'scripts/configs/linux.toml').read_text('utf-8'))
    old_scans = {item['name']: old.scan(item) for item in config['signatures']}
    new_scans = {item['name']: new.scan(item) for item in config['signatures']}
    mappings = {}
    wanted = set()
    for name, baseline in old_scans.items():
        matches = new_scans[name]
        if len(baseline) == 1 and baseline[0] in old.functions:
            if len(matches) == 1 and matches[0] in new.functions:
                mappings[baseline[0]] = matches[0]
            elif len(matches) != 1:
                wanted.add(baseline[0])
    callers = defaultdict(set)
    for match in re.finditer(b'\xe8....', old.text, re.DOTALL):
        address = old.base + match.start()
        target = address + 5 + struct.unpack_from('<i', old.text, match.start() + 1)[0]
        if target in wanted:
            caller = old.containing(address)
            if caller is not None and target in old.calls(caller):
                callers[target].add(caller)
    layouts = []
    for name in ('Actor', 'Player', 'ServerPlayer', 'Level', 'ServerLevel', 'Dimension',
                 'OverworldDimension', 'ServerNetworkHandler', 'NetworkSystem', 'Item', 'BlockType'):
        layouts.append({'class': name, 'baseline_tables': [
            {'address': hex(t['address']), 'slots': len(t['slots'])} for t in old.vtables(name)],
            'target_tables': [{'address': hex(t['address']), 'slots': len(t['slots'])} for t in new.vtables(name)],
            'slot_semantics_verified': False})
    report = {'schema': 1, 'target_bds': args.target_version, 'baseline_bds': config['version'],
              'baseline_archive_sha256': old.archive_sha256, 'target_archive_sha256': new.archive_sha256,
              'baseline_binary_sha256': old.sha256, 'target_binary_sha256': new.sha256,
              'baseline_functions': len(old.functions), 'target_functions': len(new.functions),
              'unwind_rejected': [old.unwind_rejected, new.unwind_rejected],
              'abi_verified': False, 'runtime_verified': False, 'stable_eligible': False,
              'vtable_layouts': layouts, 'entries': []}
    for signature in config['signatures']:
        baseline = old_scans[signature['name']]
        matches = new_scans[signature['name']]
        if len(baseline) != 1 or len(matches) == 1:
            continue
        name = signature['name']
        candidates = defaultdict(list)
        for address in matches:
            candidates[address].append('ambiguous_old_pattern')
        for text in STRINGS.get(name, []):
            for address in new.string_functions(text):
                candidates[address].append('string:' + text)
        class_match = re.match(r'_ZNK?(\d+)', name)
        if class_match:
            length = int(class_match[1])
            class_name = name[class_match.end():class_match.end() + length]
            classes = [class_name] + (['ServerLevel'] if class_name == 'Level' else [])
            for cls in classes:
                old_tables, new_tables = old.vtables(cls), new.vtables(cls)
                for table in old_tables:
                    slots = [i for i, address in enumerate(table['slots']) if address == baseline[0]]
                    if slots:
                        for target_table in new_tables:
                            for index, address in enumerate(target_table['slots']):
                                candidates[address].append(f'vtable:{cls}:old_slots={slots}:new_slot={index}')
        if name == '_ZN10LevelChunk8tickImplER11BlockSourceRK4TickNSt3__18functionIFvvEEE':
            for match in re.finditer(b'\x5f\xf3\x6e\x3c', new.text):
                address = new.containing(new.base + match.start())
                if address:
                    candidates[address].append('LCG_constant_0x3c6ef35f')
        old_tokens = old.fingerprint(baseline[0])
        # libc++ dropped allocator template arguments from __function::__func
        # RTTI in this BDS build. Match the method/lambda fragment rather than
        # assuming the complete encoded type name is unchanged.
        fragment = None
        use_callees = False
        use_slots = False
        if 'PlayerLocationSender24_forEachClientPlayerPair' in name:
            fragment = '20PlayerLocationSender35checkPlayerPairsAndMaybeSendPackets'
            use_callees = True
        elif 'PlayerTickManager23processPlayerNetworking' in name:
            fragment = '17PlayerTickManager23processPlayerNetworking'
        elif 'InventoryTransaction23executeWorldInteraction' in name:
            fragment = 'ZNK20InventoryTransaction18getExecuteFunctionERK15InventorySourceE3$_5'
            use_slots = True
        elif 'CommandRegistry24registerOverloadInternal' in name:
            fragment = 'PFPN15CommandRegistry10ParseTokenERS3_NS2_6SymbolE'
        if fragment:
            for typename in new.type_names_containing(fragment):
                for table in new.tables_for_encoded(typename.encode() + b'\0'):
                    if use_slots:
                        for address in table['slots']:
                            candidates[address].append('rtti_functor_slot:' + typename)
                    else:
                        for site in new.leas.get(table['address'], []):
                            caller = new.containing(site)
                            if caller is not None:
                                addresses = new.calls(caller) if use_callees else {caller}
                                for address in addresses:
                                    candidates[address].append('rtti_method_fragment:' + fragment)
        qualified = None
        if 'LanThreadManager24SendLanBroadcastResponse' in name:
            qualified = 'N9NetherNet16LanThreadManagerE'
        elif 'TransportFactoryImpl24createTransportInterface' in name:
            qualified = 'N9NetherNet12_GLOBAL__N_120TransportFactoryImplE'
        if qualified:
            old_tables = old.tables_for_encoded(qualified.encode() + b'\0', primary_only=False)
            new_tables = new.tables_for_encoded(qualified.encode() + b'\0', primary_only=False)
            for table in old_tables:
                slots = [i for i, a in enumerate(table['slots']) if old.thunk_target(a) == baseline[0]]
                for target_table in new_tables:
                    if table['offset_to_top'] != target_table['offset_to_top']:
                        continue
                    for slot in slots:
                        if slot < len(target_table['slots']):
                            address = new.thunk_target(target_table['slots'][slot])
                            candidates[address].append(f'qualified_vtable:{qualified}:top={table["offset_to_top"]}:slot={slot}:thunk_resolved')
        # Strings and functor RTTI in the function itself are stronger anchors
        # than address proximity, which changes drastically between BDS builds.
        for label in old.labels(baseline[0]):
            for address in new.functions_for_label(label):
                candidates[address].append('self_' + label[0] + ':' + label[1])
        for caller in sorted(callers[baseline[0]], key=lambda address: old.functions[address])[:15]:
            mapped_callers = {mappings[caller]} if caller in mappings else set()
            if not mapped_callers:
                labels = sorted(old.labels(caller), key=lambda label: len(label[1]), reverse=True)[:12]
                for label in labels:
                    mapped_callers.update(new.functions_for_label(label))
                mapped_callers = {address for address in mapped_callers if address in new.functions and
                                  0.25 < new.functions[address] / old.functions[caller] < 4}
                if len(mapped_callers) > 100:
                    continue
                scored = [(difflib.SequenceMatcher(None, old.fingerprint(caller), new.fingerprint(address),
                                                   autojunk=False).ratio(), address) for address in mapped_callers]
                mapped_callers = {address for score, address in sorted(scored, reverse=True)[:3] if score >= 0.45}
            for new_caller in mapped_callers:
                for address in new.calls(new_caller):
                    if old.functions.get(baseline[0]) and not 0.25 < new.functions[address] / old.functions[baseline[0]] < 4:
                        continue
                    candidates[address].append(f'callgraph:old_caller={hex(caller)}:new_caller={hex(new_caller)}')
        ranked = []
        for address, evidence in candidates.items():
            if new.containing(address) != address:
                continue
            score = difflib.SequenceMatcher(None, old_tokens, new.fingerprint(address), autojunk=False).ratio()
            ranked.append({'address': hex(address), 'similarity': round(score, 5), 'size': new.functions[address],
                           'evidence': evidence, 'head': new.fingerprint(address)[:16]})
        # Preserve the exact qualified-vtable anchor even when compiler changes
        # make an unrelated constructor score higher by instruction similarity.
        ranked.sort(key=lambda candidate: (
            any(e.startswith('qualified_vtable:') for e in candidate['evidence']),
            candidate['similarity']), reverse=True)
        entry = {'name': name, 'baseline_address': hex(baseline[0]),
                 'baseline_size': old.functions.get(baseline[0]), 'pattern_matches': len(matches),
                 'baseline_head': old_tokens[:20],
                 'candidates': ranked[:5], 'manual_abi_review_required': True}
        if ranked:
            top = ranked[0]
            top['instruction_diff'] = list(difflib.unified_diff(old_tokens, new.fingerprint(int(top['address'], 16)),
                                                               fromfile='1.26.52', tofile='1.26.60', n=2))[:150]
        report['entries'].append(entry)
        print(json.dumps({'name': name, 'candidates': [{k: c[k] for k in ('address', 'similarity')} for c in ranked[:2]]}), flush=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    # Also write an empty entry list for a fully matching control binary.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
