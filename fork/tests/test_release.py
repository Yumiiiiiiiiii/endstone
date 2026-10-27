"""Verify stable gate enforcement with synthetic metadata, never a real release."""

import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_manifest", ROOT / "release_manifest.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.commit = "a" * 40
        self.wheel = self.root / "endstone-0.11.14+ymii.gaaaaaaaaaaaa-cp313-cp313-manylinux_2_31_x86_64.whl"
        with zipfile.ZipFile(self.wheel, "w") as zipped:
            zipped.writestr("endstone.dist-info/METADATA", "Name: endstone\nVersion: 0.11.14+ymii.gaaaaaaaaaaaa\n")
        self.bds = {"version": "1.26.60", "sha256": "b" * 64, "url": "https://www.minecraft.net/fixture.zip"}
        self.proof = self.root / "proof.txt"
        self.proof.write_text("SYNTHETIC TEST FIXTURE ONLY")
        self.data = {"commit": self.commit, "wheel_sha256": release.sha256(self.wheel),
                     "bds_version": self.bds["version"], "bds_sha256": self.bds["sha256"],
                     "checks": dict.fromkeys(release.CHECKS, "passed"),
                     "evidence_files": {name: {"path": self.proof.name, "sha256": release.sha256(self.proof)} for name in release.CHECKS}}
        self.evidence = self.root / "validation.json"

    def tearDown(self):
        self.temp.cleanup()

    def assemble(self):
        self.evidence.write_text(json.dumps(self.data))
        return release.assemble(self.wheel, self.evidence, "ymii-fixture", self.commit, self.bds)

    def test_complete_artifact_bound_fixture_is_accepted(self):
        self.assertEqual(self.assemble()["commit"], self.commit)

    def test_missing_wings_check_rejected(self):
        self.data["checks"].pop("wings")
        with self.assertRaisesRegex(ValueError, "all native"):
            self.assemble()

    def test_wrong_wheel_commit_bds_or_missing_log_rejected(self):
        for key, value in [("commit", "c" * 40), ("wheel_sha256", "c" * 64),
                           ("bds_version", "1.26.52"), ("bds_sha256", "c" * 64)]:
            original = self.data[key]
            self.data[key] = value
            with self.assertRaises(ValueError):
                self.assemble()
            self.data[key] = original
        self.proof.unlink()
        with self.assertRaisesRegex(ValueError, "evidence file"):
            self.assemble()


if __name__ == "__main__":
    unittest.main()
