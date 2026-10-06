import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ManifestContract(unittest.TestCase):
    def test_native_executable_has_scoped_readers_and_report_routes(self):
        manifest = json.loads((ROOT / "manifest.json").read_text())
        self.assertEqual(manifest["kind"], "executable")
        self.assertEqual(manifest["srelensApiVersion"], "^0.8")
        self.assertTrue((ROOT / "icons/icon.svg").is_file())
        readers = {row["name"]: row for row in manifest["capabilities"]}
        self.assertEqual(len(readers), 19)
        self.assertIn("k8s.runJob", manifest["permissions"])
        for name in ("namespace-job", "namespace-config-job", "namespace-vulnerability-job", "image-job"):
            self.assertEqual(readers[name]["target"], "k8s.runJob")
            self.assertEqual(readers[name]["inputs"], [])
            self.assertRegex(readers[name]["arguments"]["image"], r"^aquasec/trivy@sha256:[0-9a-f]{64}$")
        for name in ("deployment-images", "statefulset-images", "daemonset-images"):
            self.assertEqual(readers[name]["target"], "k8s.listWorkloadImages")
            self.assertEqual(readers[name]["inputs"], ["context", "namespace"])
        operations = {row["name"]: row for row in manifest["sidecar"]["operations"]}
        self.assertTrue(operations["source-status"]["view"]["autoRun"])
        self.assertTrue(operations["findings"]["view"]["hidden"])
        self.assertTrue(operations["findings"]["view"]["autoRun"])
        self.assertEqual({row["name"] for row in operations["findings"]["inputs"] if row.get("required")}, {"clusterId", "reportId"})
        for name in ("scan-namespace", "scan-image"):
            self.assertTrue(operations[name]["view"]["stream"])
            self.assertFalse(operations[name]["view"].get("autoRun", False))
            self.assertIn("namespace", {row["name"] for row in operations[name]["inputs"] if row.get("required")})
        for name in ("namespace-job", "namespace-config-job", "namespace-vulnerability-job"):
            self.assertNotIn("--platform", " ".join(readers[name]["arguments"]["args"]))
        self.assertNotIn("requiredResources", manifest)
        self.assertEqual(manifest.get("actions", []), [])

if __name__ == "__main__": unittest.main()
