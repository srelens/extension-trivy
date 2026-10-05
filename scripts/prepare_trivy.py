#!/usr/bin/env python3
"""Prepare pinned Trivy source with reviewed sandbox and inventory fixes."""
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
APK_FILE = Path("pkg/fanal/analyzer/pkg/apk/apk.go")
APK_SOURCE_SHA = "182f5eb159ec940b04d8d97d6fce85042930c9b641e263b202ad6392f4effb51"


def prepare_source(source, target):
    source, target = Path(source), Path(target)
    original = (source / FILE).read_bytes()
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA:
        raise ValueError("Trivy source does not match the reviewed patch input")
    old, new = b"os.Chmod(f.Name(), 0o600)", b"f.Chmod(0o600)"
    if original.count(old) != 1:
        raise ValueError("Trivy patch no longer applies exactly once")
    patched = original.replace(old, new)
    apk = (source / APK_FILE).read_bytes()
    if hashlib.sha256(apk).hexdigest() != APK_SOURCE_SHA:
        raise ValueError("APK analyzer source does not match the reviewed patch input")
    marker = b"scanner := bufio.NewScanner(input.Content)"
    parsed = b"parsedPkgs, installedFiles := a.parseApkInfo(ctx, scanner)"
    if apk.count(marker) != 1 or apk.count(parsed) != 1:
        raise ValueError("APK analyzer patch no longer applies exactly once")
    apk = apk.replace(marker, marker + b"\n\tscanner.Buffer(make([]byte, 64*1024), 4*1024*1024)")
    apk = apk.replace(parsed, parsed + b'\n\tif err := scanner.Err(); err != nil {\n\t\treturn nil, &trivytypes.UserError{Message: fmt.Sprintf("incomplete APK inventory: %v", err)}\n\t}')
    # The upstream analyzer dispatcher propagates UserError; ordinary errors
    # are logged and skipped, which would hide this incomplete inventory.
    apk = apk.replace(b'"github.com/aquasecurity/trivy/pkg/fanal/types"', b'"github.com/aquasecurity/trivy/pkg/fanal/types"\n\ttrivytypes "github.com/aquasecurity/trivy/pkg/types"')
    patches = {FILE: patched, APK_FILE: apk}
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
                expected_bytes = patches.get(relative, original_file.read_bytes())
                if copied_file.read_bytes() != expected_bytes:
                    raise ValueError(f"existing .trivy differs at {relative}")
    else:
        shutil.copytree(source, target)
        for relative, content in patches.items():
            (target / relative).chmod(0o644)
            (target / relative).write_bytes(content)
    return patched


def main():
    downloaded = json.loads(subprocess.check_output(["go", "mod", "download", "-json", MODULE + "@" + VERSION], cwd=ROOT))
    if downloaded.get("Version") != VERSION or downloaded.get("Error"):
        raise ValueError("pinned Trivy source download failed")
    if downloaded.get("Sum") != MODULE_SUM:
        raise ValueError("Trivy module checksum does not match the pinned source")
    patched = prepare_source(downloaded["Dir"], ROOT / ".trivy")
    print(f"Trivy {VERSION} + fd-chmod and complete APK inventory patches; upstream module checksum: {downloaded['Sum']}")
    print(f"patched file sha256:{hashlib.sha256(patched).hexdigest()}")


if __name__ == "__main__":
    main()
