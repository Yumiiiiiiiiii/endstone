"""Isolated CI probe; never included in the production plugin directory."""

import json
from pathlib import Path

from endstone.plugin import Plugin


class ForkProbe(Plugin):
    api_version = "0.11"
    commands = {"forkprobe": {"description": "CI health probe", "usages": ["/forkprobe"]}}

    def on_enable(self):
        self.server.scheduler.run_task(self, self.probe, delay=20)

    def probe(self):
        data = {
            "bds": self.server.minecraft_version,
            "protocol": self.server.protocol_version,
            "endstone": self.server.version,
            "scheduler": True,
        }
        Path("fork-probe.json").write_text(json.dumps(data), encoding="utf-8")
        self.logger.info("FORK_SCHEDULER_OK")

    def on_command(self, sender, command, args):
        sender.send_message("FORK_COMMAND_OK")
        return True

    def on_disable(self):
        self.logger.info("FORK_DISABLE_OK")
