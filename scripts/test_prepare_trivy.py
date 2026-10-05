import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("prepare_trivy", Path(__file__).with_name("prepare_trivy.py"))
prepare_trivy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare_trivy)


class TrivySourcePinTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "upstream"
        self.target = Path(self.temp.name) / "private-copy"
        source_file = self.source / prepare_trivy.FILE
        source_file.parent.mkdir(parents=True)
        self.original = b"before\nos.Chmod(f.Name(), 0o600)\nafter\n"
        source_file.write_bytes(self.original)
        self.apk_original = b"scanner := bufio.NewScanner(input.Content)\nparsedPkgs, installedFiles := a.parseApkInfo(ctx, scanner)\n"
        apk_file = self.source / "pkg/fanal/analyzer/pkg/apk/apk.go"
        apk_file.parent.mkdir(parents=True)
        apk_file.write_bytes(self.apk_original)
        apk_pin = patch.object(prepare_trivy, "APK_SOURCE_SHA", hashlib.sha256(self.apk_original).hexdigest(), create=True)
        apk_pin.start()
        self.addCleanup(apk_pin.stop)
        (self.source / "other.go").write_text("pinned scanner code")
        (self.source / "LICENSE").write_text("upstream license")
        pinned = patch.object(prepare_trivy, "SOURCE_SHA", hashlib.sha256(self.original).hexdigest())
        pinned.start()
        self.addCleanup(pinned.stop)

    def test_repeat_preparation_rejects_other_source_drift_and_preserves_it(self):
        prepare_trivy.prepare_source(self.source, self.target)
        self.assertEqual((self.target / prepare_trivy.FILE).read_bytes(), self.original.replace(b"os.Chmod(f.Name(), 0o600)", b"f.Chmod(0o600)"))
        self.assertEqual((self.target / "LICENSE").read_text(), "upstream license")
        self.assertEqual((self.source / prepare_trivy.FILE).read_bytes(), self.original)
        prepare_trivy.prepare_source(self.source, self.target)
        (self.target / "other.go").write_text("unpinned code")
        with self.assertRaises(ValueError):
            prepare_trivy.prepare_source(self.source, self.target)
        self.assertEqual((self.target / "other.go").read_text(), "unpinned code")

    def test_unpinned_patch_input_is_refused_before_copy(self):
        (self.source / prepare_trivy.FILE).write_text("different upstream revision")
        with self.assertRaises(ValueError):
            prepare_trivy.prepare_source(self.source, self.target)
        self.assertFalse(self.target.exists())

    def test_apk_scanner_checks_failed_reads_and_allows_bounded_long_lines(self):
        prepare_trivy.prepare_source(self.source, self.target)
        patched = (self.target / "pkg/fanal/analyzer/pkg/apk/apk.go").read_bytes()
        self.assertIn(b"scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)", patched)
        self.assertIn(b"scanner.Err()", patched)
        self.assertEqual((self.source / "pkg/fanal/analyzer/pkg/apk/apk.go").read_bytes(), self.apk_original)
        (self.source / "pkg/fanal/analyzer/pkg/apk/apk.go").write_text("unreviewed code")
        with self.assertRaises(ValueError):
            prepare_trivy.prepare_source(self.source, self.target)

    def test_extra_or_symlink_source_in_existing_copy_is_refused(self):
        prepare_trivy.prepare_source(self.source, self.target)
        extra = self.target / "extra.go"
        extra.write_text("extra scanner code")
        with self.assertRaises(ValueError):
            prepare_trivy.prepare_source(self.source, self.target)
        extra.unlink()
        original = self.target / "other.go"
        original.unlink()
        original.symlink_to(self.source / "other.go")
        with self.assertRaises(ValueError):
            prepare_trivy.prepare_source(self.source, self.target)


if __name__ == "__main__":
    unittest.main()
