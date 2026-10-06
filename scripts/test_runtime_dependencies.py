"""The normal controller build must never pull in the local Trivy engine."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RuntimeDependencies(unittest.TestCase):
    def test_all_default_packages_exclude_trivy_engine_dependencies(self):
        modules = subprocess.check_output(
            ["go", "list", "-deps", "-f", "{{with .Module}}{{.Path}}{{end}}", "./..."],
            cwd=ROOT, text=True,
        ).splitlines()
        scanner_modules = {name for name in modules if name.startswith("github.com/aquasecurity/")}
        self.assertEqual(scanner_modules, set(), "The local scanner belongs in the optional proof module")


if __name__ == "__main__":
    unittest.main()
