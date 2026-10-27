"""Report upstream and Mojang updates; never guess native compatibility."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-issues", action="store_true", help="Record an unsupported BDS in this Fork")
    args = parser.parse_args()
    config = json.loads((ROOT / "fork/config.json").read_text())
    upstream = json.loads(subprocess.check_output(
        ["gh", "api", f"repos/{config['upstream']}/commits/main"], text=True))
    request = urllib.request.Request("https://net-secondary.web.minecraft-services.net/api/v1.0/download/links",
                                     headers={"User-Agent": "Endstone-Fork-Monitor/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        links = json.load(response)["result"]["links"]
    linux = next(item["downloadUrl"] for item in links if item["downloadType"] == "serverBedrockLinux")
    match = re.search(r"bedrock-server-(1\.\d+\.\d+)\.(\d+)\.zip$", linux)
    if not match:
        raise ValueError("Mojang returned an unknown BDS release format")
    result = {"schema": 1, "upstream_sha": upstream["sha"], "upstream_url": upstream["html_url"],
              "bds_version": match[1], "bds_build": match[2], "bds_url": linux,
              "configured_native_bds": config["native_bds"],
              "native_port_required": match[1] != config["native_bds"],
              "stable_eligible": False}
    Path("reports").mkdir(exist_ok=True)
    Path("reports/updates.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.record_issues and result["native_port_required"]:
        repository = config["repository"]
        if repository != "Yumiiiiiiiiii/endstone":
            raise ValueError("Issue writes must target the configured personal Fork")
        issues = json.loads(subprocess.check_output([
            "gh", "issue", "list", "--repo", repository, "--state", "open", "--search",
            f"BDS {match[1]} in:title", "--json", "number,title",
        ], text=True))
        if not any(f"BDS {match[1]} " in item["title"] for item in issues):
            body = Path("reports/native-port-required.md")
            body.write_text(
                f"Mojang now distributes BDS {match[1]}.{match[2]}.\n\n"
                f"The Fork native target is {config['native_bds']}. No compatibility is claimed.\n\n"
                f"Upstream: {upstream['html_url']}\nBDS: {linux}\n\n"
                "Run fork/probe_bds.py against the new binary, review signatures, ABI and structures, "
                "then run the complete player/plugin/Docker/Wings tests on a development branch. "
                "Do not change version constants alone or promote an unverified native port.\n",
                encoding="utf-8",
            )
            subprocess.run(["gh", "issue", "create", "--repo", repository, "--title",
                            f"BDS {match[1]} native ABI port required", "--body-file", str(body)], check=True)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
