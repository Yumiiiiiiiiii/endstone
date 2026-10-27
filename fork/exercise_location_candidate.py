"""Exercise one BDS Linux function candidate; never load Endstone or certify a server.

Only the checksum-pinned PlayerLocationSender function is mapped. Its two PLT
calls are resolved to host libm. No BDS initializer, hook or server is started.
Run in a disposable Linux x86-64 process, preferably under unshare --net.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import io
import json
import mmap
import platform
import random
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM
from capstone.x86_const import X86_REG_RIP
from elftools.elf.elffile import ELFFile

from analyze_linux_bds import Binary

BUILDS = {
    "baseline": ("f6348d84fa714d04ca194f207e89453ca6bba0a1359396475271a52a150471c6", 0xc80f880),
    "target": ("cbbd5414fa6a310353ed1fc76a0ba691c3fd1ea852fd04bb76764ee4c1afdb98", 0xcdefbc0),
}


class Vec3(C.Structure):
    _fields_ = [("x", C.c_float), ("y", C.c_float), ("z", C.c_float)]


class OptionalVec3(C.Structure):
    _fields_ = [("value", Vec3), ("present", C.c_bool), ("padding", C.c_ubyte * 3)]


class Location(C.Structure):
    _fields_ = [("position", OptionalVec3), ("dimension", C.c_int32), ("spectator", C.c_bool)]


class Candidate:
    def __init__(self, archive, build):
        expected, entry = BUILDS[build]
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            raise ValueError("Candidate exercise is restricted to the reviewed exact Mojang archive")
        binary = Binary(archive)
        self.archive_sha256, self.binary_sha256 = binary.archive_sha256, binary.sha256
        self.entry = entry
        size = binary.functions[entry]
        code = bytearray(binary.text[entry - binary.base:entry - binary.base + size])
        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        disassembler.detail = True
        instructions = list(disassembler.disasm(code, entry))
        if sum(i.size for i in instructions) != size:
            raise ValueError("Incomplete candidate disassembly")
        elf = ELFFile(io.BytesIO(binary.raw))
        symbols = elf.get_section_by_name(".dynsym")
        relocations = {r["r_offset"]: symbols.get_symbol(r["r_info_sym"]).name
                       for r in elf.get_section_by_name(".rela.plt").iter_relocations()}
        constants, calls = {}, []
        for ins in instructions:
            if ins.mnemonic.startswith("call"):
                if len(ins.operands) != 1 or ins.operands[0].type != CS_OP_IMM or ins.bytes[0] != 0xe8:
                    raise ValueError("Unexpected candidate call")
                destination = ins.operands[0].imm
                offset = binary.file_offset(destination)
                if offset is None or binary.raw[offset:offset + 2] != b"\xff\x25":
                    raise ValueError("Expected a reviewed PLT call")
                got = destination + 6 + struct.unpack_from("<i", binary.raw, offset + 2)[0]
                name = relocations.get(got)
                if name not in {"atan2f", "fmodf"}:
                    raise ValueError("Candidate calls an unreviewed external symbol")
                calls.append((ins.address, name))
            if ins.mnemonic.startswith("j"):
                if len(ins.operands) != 1 or ins.operands[0].type != CS_OP_IMM or not entry <= ins.operands[0].imm < entry + size:
                    raise ValueError("Candidate branches outside the reviewed function")
            for operand in ins.operands:
                if operand.type == CS_OP_MEM and operand.mem.base == X86_REG_RIP:
                    target = ins.address + ins.size + operand.mem.disp
                    offset = binary.file_offset(target)
                    if offset is None or operand.access & 2 or operand.size != 4:
                        raise ValueError("Unexpected RIP-relative candidate access")
                    constants[target] = binary.raw[offset:offset + operand.size]
        if {name for _, name in calls} != {"atan2f", "fmodf"}:
            raise ValueError("Reviewed candidate math calls are missing")
        page = mmap.PAGESIZE
        low = min([entry, *constants]) & -page
        code_page = entry & -page
        high = (entry + size + 128 + page - 1) & -page
        self.memory = mmap.mmap(-1, high - low, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        address = C.addressof(C.c_char.from_buffer(self.memory))
        self.math_counts, self.callbacks = {}, []
        libm = C.CDLL("libm.so.6")
        for index, (site, name) in enumerate(calls):
            operation = getattr(libm, name)
            operation.argtypes, operation.restype = [C.c_float, C.c_float], C.c_float
            self.math_counts[name] = 0

            def counted(x, y, operation=operation, name=name):
                self.math_counts[name] += 1
                return operation(x, y)

            callback = C.CFUNCTYPE(C.c_float, C.c_float, C.c_float)(counted)
            self.callbacks.append(callback)
            trampoline = entry + size + index * 16
            stub = b"\x48\xb8" + struct.pack("<Q", C.cast(callback, C.c_void_p).value) + b"\xff\xe0"
            self.memory[trampoline - low:trampoline - low + len(stub)] = stub
            struct.pack_into("<i", code, site - entry + 1, trampoline - site - 5)
        self.memory[entry - low:entry - low + size] = code
        for target, data in constants.items():
            self.memory[target - low:target - low + len(data)] = data
        protect = C.CDLL(None, use_errno=True).mprotect
        protect.argtypes, protect.restype = [C.c_void_p, C.c_size_t, C.c_int], C.c_int

        def protection(start, length, flags):
            if protect(address + start - low, length, flags):
                raise OSError(C.get_errno(), "mprotect failed")

        protection(low, high - low, 0)
        for target in {x & -page for x in constants}:
            protection(target, page, mmap.PROT_READ)
        protection(code_page, high - code_page, mmap.PROT_READ | mmap.PROT_EXEC)
        signature = C.CFUNCTYPE(C.c_bool, C.POINTER(Vec3), C.c_int32, C.c_bool,
                               C.POINTER(OptionalVec3), C.POINTER(Location), C.c_float)
        self.function = signature(address + entry - low)
        self.size = size


def exercise(baseline, target):
    if sys.platform != "linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise ValueError("This candidate exercise requires Linux x86-64")
    assert C.sizeof(Vec3) == 12 and C.sizeof(OptionalVec3) == 16 and C.sizeof(Location) == 24
    assert Location.dimension.offset == 16 and Location.spectator.offset == 20
    old, new = Candidate(baseline, "baseline"), Candidate(target, "target")
    randomizer = random.Random(2660)
    mismatches, counts = [], {"cases": 0, "true": 0, "false": 0}
    for iteration in range(20000):
        viewer = Vec3(*(randomizer.uniform(-4096, 4096) for _ in range(3)))
        position = Vec3(*(randomizer.uniform(-4096, 4096) for _ in range(3)))
        previous = OptionalVec3(position if iteration % 3 == 0 else viewer, bool(iteration & 1))
        observed = Location(OptionalVec3(position, bool(iteration & 2)), iteration % 3, bool(iteration & 4))
        dimension, spectator = (iteration // 3) % 3, bool(iteration & 8)
        threshold = (0.0, 1.0, 16.0, 128.0, 4096.0)[iteration % 5]
        before = bytes(viewer) + bytes(previous) + bytes(observed)
        a = old.function(viewer, dimension, spectator, previous, observed, threshold)
        b = new.function(viewer, dimension, spectator, previous, observed, threshold)
        if before != bytes(viewer) + bytes(previous) + bytes(observed):
            raise AssertionError("Candidate unexpectedly wrote to argument memory")
        if a != b:
            mismatches.append({"case": iteration, "baseline": a, "target": b})
        counts["cases"] += 1
        counts["true" if b else "false"] += 1
    if any(not n for candidate in (old, new) for n in candidate.math_counts.values()):
        raise AssertionError("The math paths were not exercised")
    return {"schema": 1, "function": "PlayerLocationSender::_shouldSendPositionPacket",
            "baseline_archive_sha256": old.archive_sha256, "target_archive_sha256": new.archive_sha256,
            "baseline_binary_sha256": old.binary_sha256, "target_binary_sha256": new.binary_sha256,
            "baseline_address": hex(old.entry), "target_address": hex(new.entry),
            "argument_layout": {"Vec3": 12, "optional_Vec3": 16, "PlayerLocationData": 24,
                                "dimension_offset": 16, "spectator_offset": 20},
            "layout_scope": "Synthetic argument buffers; target sizeof and complete class layout are not proven",
            "counts": counts, "math_calls": {"baseline": old.math_counts, "target": new.math_counts},
            "mismatches": mismatches[:20], "mismatch_count": len(mismatches),
            "status": "passed" if not mismatches else "failed", "native_abi_verified": False,
            "endstone_runtime_verified": False, "stable_eligible": False,
            "limitations": ["Isolated function calls only", "Host libm replaces two BDS PLT math calls",
                            "No hook installation, server initialization, player or integration validation"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = exercise(args.baseline, args.target)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
