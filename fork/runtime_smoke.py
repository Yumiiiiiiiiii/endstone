"""Start and restart a scratch BDS world using the installed Fork wheel."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_server(folder: Path, expected_bds: str, log_path: Path) -> dict:
    env = os.environ.copy()
    env["ENDSTONE_PYTHON_EXECUTABLE"] = sys.executable
    process = subprocess.Popen(
        [sys.executable, "-m", "endstone", "-s", str(folder), "-y", "--no-interactive"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", env=env, cwd=folder,
    )
    lines = []
    messages = queue.Queue()

    def read():
        for line in process.stdout:
            messages.put(line)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()

    def wait_for(marker: str, timeout: float):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(marker in line for line in lines):
                return
            if process.poll() is not None and messages.empty():
                raise RuntimeError(f"BDS exited {process.returncode} while waiting for {marker}")
            try:
                line = messages.get(timeout=0.25)
                lines.append(line)
                logfile.write(line)
                logfile.flush()
            except queue.Empty:
                pass
        raise TimeoutError(f"BDS did not produce {marker}")

    with log_path.open("w", encoding="utf-8") as logfile:
        try:
            wait_for("Server started", 240)
            wait_for("FORK_SCHEDULER_OK", 30)
            probe = json.loads((folder / "fork-probe.json").read_text("utf-8"))
            actual = probe["bds"]
            actual = actual if actual.startswith("1.") else "1." + actual
            if actual != expected_bds:
                raise ValueError(f"Native BDS mismatch: {actual} != {expected_bds}")
            process.stdin.write("forkprobe\n")
            process.stdin.flush()
            wait_for("FORK_COMMAND_OK", 15)
            process.stdin.write("stop\n")
            process.stdin.flush()
            wait_for("FORK_DISABLE_OK", 40)
            process.wait(timeout=40)
            if process.returncode != 0:
                raise RuntimeError(f"BDS exited {process.returncode}")
            world = folder / "worlds/ForkCI/db/CURRENT"
            if not world.is_file():
                raise RuntimeError("Saved world database is missing")
            return probe
        finally:
            if process.poll() is None:
                try:
                    process.stdin.write("stop\n")
                    process.stdin.flush()
                    process.wait(timeout=30)
                except (OSError, subprocess.TimeoutExpired):
                    process.kill()
                    process.wait(timeout=10)
            reader.join(timeout=5)
            while not messages.empty():
                logfile.write(messages.get_nowait())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bds", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"1\.\d+\.\d+", args.bds):
        raise ValueError("Invalid BDS version")
    folder = ROOT / ".cache/fork-smoke"
    if folder.exists():
        raise FileExistsError(f"Scratch folder already exists: {folder}; preserve or move it before retrying")
    folder.mkdir(parents=True)
    installed = subprocess.check_output(
        [sys.executable, "-c", "import importlib.metadata as m; print(m.version('endstone'))"],
        cwd=folder, text=True,
    ).strip()
    if "+ymii.g" not in installed:
        raise ValueError(f"Runtime smoke requires the installed Fork wheel, got {installed}")
    (folder / "server.properties").write_text(
        "server-name=Fork CI\nlevel-name=ForkCI\nserver-port=29192\nserver-portv6=29193\n"
        "online-mode=true\nenable-lan-visibility=false\nview-distance=4\nmax-players=2\n",
        encoding="utf-8",
    )
    (folder / "endstone.toml").write_text("[network]\nipv6=false\nstun-servers=[]\n", encoding="utf-8")
    subprocess.run([sys.executable, "-m", "build", "--wheel", str(ROOT / "fork/smoke_plugin"),
                    "--outdir", str(folder / "probe-wheel")], check=True)
    (folder / "plugins").mkdir()
    wheel = next((folder / "probe-wheel").glob("*.whl"))
    shutil.copy2(wheel, folder / "plugins" / wheel.name)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result = {"schema": 1, "bds_version": args.bds, "commit": os.environ.get("GITHUB_SHA"),
              "checks": {}, "stable_eligible": False}
    try:
        result["probe"] = run_server(folder, args.bds, args.output.with_suffix(".boot.log"))
        (folder / "fork-probe.json").unlink()
        result["restart_probe"] = run_server(folder, args.bds, args.output.with_suffix(".restart.log"))
        result["checks"] = {name: "passed" for name in ("boot", "commands", "scheduler", "world_save_restart")}
        result["world_current_sha256"] = hashlib.sha256((folder / "worlds/ForkCI/db/CURRENT").read_bytes()).hexdigest()
    except Exception as exc:
        result["error"] = str(exc)
        raise
    finally:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
