#!/usr/bin/env python3
"""Prepare pinned Trivy source with its one-line sandbox compatibility patch."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MODULE = "github.com/aquasecurity/trivy"
VERSION = "v0.75.0"
FILE = Path("pkg/fanal/analyzer/fs.go")
SOURCE_SHA = "4877b47e37516bbd2de578f82f3dacd4ea454b36ab5a20f36d606d4f4ffb09bc"
MODULE_SUM = "h1:iOMkI0qX3Dfo+A6lznchBvtDD4ZSu+H9RBww1z5Qz58="


def prepare_source(source, target):
    source, target = Path(source), Path(target)
    original = (source / FILE).read_bytes()
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA:
        raise ValueError("Trivy source does not match the reviewed patch input")
    old, new = b"os.Chmod(f.Name(), 0o600)", b"f.Chmod(0o600)"
    if original.count(old) != 1:
        raise ValueError("Trivy patch no longer applies exactly once")
    patched = original.replace(old, new)
    if target.exists():
        expected = {p.relative_to(source) for p in source.rglob("*")}
        actual = {p.relative_to(target) for p in target.rglob("*")}
        if target.is_symlink() or expected != actual:
            raise ValueError("existing .trivy differs; preserve it and prepare a clean directory")
        for relative in expected:
            original_file, copied_file = source / relative, target / relative
            if copied_file.is_symlink() or original_file.is_dir() != copied_file.is_dir():
                raise ValueError(f"existing .trivy differs at {relative}")
            if original_file.is_file():
                expected_bytes = patched if relative == FILE else original_file.read_bytes()
                if copied_file.read_bytes() != expected_bytes:
                    raise ValueError(f"existing .trivy differs at {relative}")
    else:
        shutil.copytree(source, target)
        (target / FILE).chmod(0o644)
        (target / FILE).write_bytes(patched)
    return patched


def main():
    downloaded = json.loads(subprocess.check_output(["go", "mod", "download", "-json", MODULE + "@" + VERSION], cwd=ROOT))
    if downloaded.get("Version") != VERSION or downloaded.get("Error"):
        raise ValueError("pinned Trivy source download failed")
    if downloaded.get("Sum") != MODULE_SUM:
        raise ValueError("Trivy module checksum does not match the pinned source")
    patched = prepare_source(downloaded["Dir"], ROOT / ".trivy")
    print(f"Trivy {VERSION} + fd-chmod patch; upstream module checksum: {downloaded['Sum']}")
    print(f"patched file sha256:{hashlib.sha256(patched).hexdigest()}")


if __name__ == "__main__":
    main()
