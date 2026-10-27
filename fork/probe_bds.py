"""Run the upstream symbol scanner without changing native headers or claiming ABI compatibility."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import logging
import re
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

import lief
import requests

ROOT = Path(__file__).resolve().parents[1]


def probe(version: str, platform: str, output: Path) -> dict:
    if not re.fullmatch(r"1\.\d+\.\d+", version):
        raise ValueError("Use an exact BDS release version, for example 1.26.60")
    spec = importlib.util.spec_from_file_location("endstone_symbol_scanner", ROOT / "scripts/dump_symbols.py")
    scanner = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = scanner
    spec.loader.exec_module(scanner)
    scanner.CACHE_DIR = ROOT / ".cache/fork-bds"
    scanner.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    config = tomllib.loads((ROOT / f"scripts/configs/{platform}.toml").read_text("utf-8"))
    baseline = config["version"]
    config["version"] = version
    archive = scanner.download_server(version, platform)
    metadata_url = f"{scanner.BASE_RAW_URL}/release/{version}/metadata.json"
    response = requests.get(metadata_url, timeout=30)
    response.raise_for_status()
    archive_hash = hashlib.sha256(Path(archive).read_bytes()).hexdigest()
    expected_hash = response.json()["binary"][platform]["sha256"]
    if archive_hash != expected_hash:
        raise ValueError("Downloaded BDS archive does not match metadata SHA256")
    binary_name = "bedrock_server.exe" if platform == "windows" else "bedrock_server"
    with ZipFile(archive) as zipped:
        raw = zipped.read(binary_name)
    binary = lief.parse(raw)
    section = binary.get_section(".text")
    if section is None:
        raise ValueError("BDS binary has no .text section")
    ambiguous = []

    class ScanWarnings(logging.Handler):
        def emit(self, record):
            if "Ambiguous pattern" in record.getMessage():
                ambiguous.append(record.getMessage())

    handler = ScanWarnings()
    scanner.logger.addHandler(handler)
    try:
        resolved = scanner.scan_signatures(section, config)
    finally:
        scanner.logger.removeHandler(handler)
    unresolved = sorted(name for name, address in resolved.items() if not address)
    report = {
        "schema": 1,
        "archive_filename": Path(archive).name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target_bds": version,
        "baseline_bds": baseline,
        "platform": platform,
        "binary_sha256": hashlib.sha256(raw).hexdigest(),
        "archive_sha256": archive_hash,
        "signatures": len(config["signatures"]),
        "resolved": sum(bool(address) for address in resolved.values()),
        "unresolved": unresolved,
        "ambiguous": ambiguous,
        "offsets": resolved,
        "abi_verified": False,
        "runtime_verified": False,
        "stable_eligible": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "offsets"}, indent=2))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", choices=["windows", "linux"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.version, args.platform, args.output)
    return 1 if report["unresolved"] or report["ambiguous"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
