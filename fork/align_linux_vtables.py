"""Propose vtable slot alignment; never edit C++ headers or certify an ABI."""
from __future__ import annotations

import argparse
import difflib
import json
import re
from functools import lru_cache
from pathlib import Path

from analyze_linux_bds import Binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--target-version', default='1.26.60')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'1\.\d+\.\d+', args.target_version):
        parser.error('Use a BDS version such as 1.26.60')
    old, new = Binary(args.baseline), Binary(args.target)

    @lru_cache(None)
    def similarity(a, b):
        return difflib.SequenceMatcher(None, old.fingerprint(a)[:200], new.fingerprint(b)[:200], autojunk=False).ratio()

    report = {'target_bds': args.target_version, 'baseline_binary_sha256': old.sha256,
              'target_binary_sha256': new.sha256, 'abi_verified': False, 'runtime_verified': False,
              'stable_eligible': False, 'manual_review_required': True,
              'limitations': 'Equal or similar implementations may make insertion locations ambiguous. '
                             'Slot alignment does not establish method names, argument types or field layouts.',
              'classes': []}
    for name in ('Player', 'ServerPlayer', 'Dimension', 'ServerNetworkHandler', 'Item', 'BlockType'):
        a, b = old.vtables(name)[0]['slots'], new.vtables(name)[0]['slots']
        scores, trace = {(0, 0): 0.0}, {}
        for i in range(len(a) + 1):
            for j in range(max(0, i - 10), min(len(b), i + 10) + 1):
                if i == j == 0:
                    continue
                choices = []
                if i and j and (i - 1, j - 1) in scores:
                    choices.append((scores[i - 1, j - 1] + 2 * similarity(a[i - 1], b[j - 1]) - 1, 'match'))
                if i and (i - 1, j) in scores:
                    choices.append((scores[i - 1, j] - 0.5, 'delete'))
                if j and (i, j - 1) in scores:
                    choices.append((scores[i, j - 1] - 0.5, 'insert'))
                if choices:
                    scores[i, j], trace[i, j] = max(choices)
        i, j = len(a), len(b)
        operations = []
        while i or j:
            operation = trace[i, j]
            if operation == 'match':
                i, j = i - 1, j - 1
                operations.append({'old_slot': i, 'new_slot': j, 'old_address': hex(a[i]),
                                   'new_address': hex(b[j]), 'similarity': round(similarity(a[i], b[j]), 4)})
            elif operation == 'insert':
                j -= 1
                operations.append({'new_slot': j, 'new_address': hex(b[j]), 'change': 'candidate_insert',
                                   'instructions': [x.mnemonic + ' ' + x.op_str for x in new.instructions(b[j])][:35]})
            else:
                i -= 1
                operations.append({'old_slot': i, 'old_address': hex(a[i]), 'change': 'candidate_delete'})
        operations.reverse()
        report['classes'].append({'class': name, 'old_count': len(a), 'new_count': len(b), 'alignment': operations})
        print(json.dumps({'class': name, 'candidate_insertions': [op['new_slot'] for op in operations
                                                                if op.get('change') == 'candidate_insert']}), flush=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
