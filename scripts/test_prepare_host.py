import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("prepare_host", Path(__file__).with_name("prepare_host.py"))
prepare_host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare_host)


class HostPinTest(unittest.TestCase):
    def test_exact_commit_and_preserved_existing_checkout(self):
        with tempfile.TemporaryDirectory() as root:
            source, target = Path(root) / "source", Path(root) / "host"
            source.mkdir()
            def git(*args):
                return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()
            git("init", "-q")
            (source / "first").write_text("first")
            git("add", "first")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "test: first")
            revision = git("rev-parse", "HEAD")
            (source / "second").write_text("second")
            git("add", "second")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "test: second")
            prepare_host.prepare(str(source), target, revision)
            self.assertTrue((target / "first").exists())
            self.assertFalse((target / "second").exists())
            (target / "local-work").write_text("keep me")
            prepare_host.prepare(str(source), target, revision)
            with self.assertRaises(ValueError):
                prepare_host.prepare(str(source), target, git("rev-parse", "HEAD"))
            self.assertEqual((target / "local-work").read_text(), "keep me")
            self.assertFalse((target / "second").exists())
            (target / "first").write_text("modified tracked source")
            with self.assertRaises(ValueError):
                prepare_host.prepare(str(source), target, revision)
            subprocess.run(["git", "-C", str(target), "add", "first"], check=True)
            with self.assertRaises(ValueError):
                prepare_host.prepare(str(source), target, revision)
            self.assertEqual((target / "first").read_text(), "modified tracked source")
            subprocess.run(["git", "-C", str(target), "reset", "--hard", revision], check=True, stdout=subprocess.DEVNULL)
            sdk = target / "sdk/go/sidecar"
            sdk.mkdir(parents=True)
            (sdk / "drift.go").write_text("package sidecar\nfunc init() {}\n")
            with self.assertRaises(ValueError):
                prepare_host.prepare(str(source), target, revision)
            self.assertTrue((sdk / "drift.go").exists())


if __name__ == "__main__":
    unittest.main()
