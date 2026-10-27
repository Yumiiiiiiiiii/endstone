"""Assemble a stable manifest only from complete, artifact-bound runtime evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from email.parser import BytesParser
from pathlib import Path

CHECKS = {"native_abi", "boot", "commands", "scheduler", "world_save_restart", "player_events",
          "block_entity", "network", "plugins", "docker", "wings"}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assemble(wheel: Path, evidence_path: Path, tag: str, commit: str, bds: dict):
    if not re.fullmatch(r"ymii-[A-Za-z0-9_.+-]+", tag) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Use a Fork release tag and full commit SHA")
    wheel_sha = sha256(wheel)
    evidence = json.loads(evidence_path.read_text("utf-8"))
    if evidence.get("commit") != commit or evidence.get("wheel_sha256") != wheel_sha:
        raise ValueError("Validation must identify this exact Fork commit and wheel SHA256")
    if evidence.get("bds_version") != bds["version"] or evidence.get("bds_sha256") != bds["sha256"]:
        raise ValueError("Runtime evidence must identify the actual BDS artifact")
    if any(evidence.get("checks", {}).get(name) != "passed" for name in CHECKS):
        raise ValueError("Stable requires all native/player/plugin/Docker/Wings runtime tests")
    if not re.fullmatch(r"[0-9a-f]{40}", evidence.get("runtime_commit", "")):
        raise ValueError("Runtime evidence must identify the exact Pterodactyl Fork commit")
    for field in ("docker_image_digest", "installer_image_digest"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", evidence.get(field, "")):
            raise ValueError(f"Runtime evidence requires a tested {field}")
    for check in CHECKS:
        record = evidence.get("evidence_files", {}).get(check, {})
        path = (evidence_path.parent / record.get("path", "")).resolve()
        if not path.is_relative_to(evidence_path.parent.resolve()) or not path.is_file() or sha256(path) != record.get("sha256"):
            raise ValueError(f"Missing or invalid evidence file for {check}")
    with zipfile.ZipFile(wheel) as zipped:
        metadata_name = next(name for name in zipped.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(zipped.read(metadata_name))
    version = metadata["Version"]
    if metadata["Name"] != "endstone" or "+ymii.g" + commit[:12] not in version:
        raise ValueError("Wheel is not the expected Fork build")
    if not wheel.name.endswith("-cp313-cp313-manylinux_2_31_x86_64.whl"):
        raise ValueError("Expected cp313 Linux x86-64 wheel from Fork CI")
    repo = "Yumiiiiiiiiii/endstone"
    return {"schema": 1, "repository": repo, "channel": "stable", "release": tag,
            "commit": commit, "endstone_version": version, "python_tag": "cp313",
            "wheel": {"filename": wheel.name, "sha256": wheel_sha,
                      "url": f"https://github.com/{repo}/releases/download/{tag}/{wheel.name}"},
            "bds": bds, "plugins": evidence.get("plugins", []),
            **({"relay": evidence["relay"]} if evidence.get("relay") else {}),
            "runtime": {"repository": "Yumiiiiiiiiii/pterodactyl", "commit": evidence["runtime_commit"],
                        "image_digest": evidence["docker_image_digest"],
                        "installer_digest": evidence["installer_image_digest"]},
            "validation": {"commit": commit, "checks": evidence["checks"], "report_sha256": sha256(evidence_path)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--bds-metadata", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads(args.bds_metadata.read_text("utf-8-sig"))
    bds = {"version": metadata["version"], **metadata["binary"]["linux"]}
    result = assemble(args.wheel, args.evidence, args.tag, args.commit, bds)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
