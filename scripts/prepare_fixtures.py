#!/usr/bin/env python3
"""Download pinned test inputs on the development host, never in the sidecar."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / ".fixtures"
IMAGE = "ghcr.io/aquasecurity/trivy-test-images@sha256:7746df395af22f04212cd25a92c1d6dbc5a06a0ca9579a229ef43008d4d1302a"
CONFIG = "055936d3920576da37aa9bc460d70c5f212028bda1c08c0879aedf03d7a66ea1"
LAYER = "e7c96db7181be991f19a9fb6975cdbbd73c65f4a2681348e63a141a2192a5f10"
DB_SOURCES = {
    "alpine.yaml": "e8454df110f7d75d368e5b4d2c9581eb3ee5c6c3118fc698d6fd824ec2573a34",
    "vulnerability.yaml": "b8167a98a187774a3944c9f63e77685bd9f38f1ec2c75c48cb00eead4707cdc4",
    "debian.yaml": "613f84285604a4a79b5595e3adbce4e73c22e7d78aa87c7530d76bc45620ea64",
}


def canonical_archive(source, target):
    # Docker export metadata differs between daemon versions. Retain the
    # verified config/layer bytes and give the outer tar deterministic headers.
    with tarfile.open(source) as archive:
        manifest = json.load(archive.extractfile("manifest.json"))
        if len(manifest) != 1 or len(manifest[0]["Layers"]) != 1:
            raise ValueError("the pinned fixture must contain exactly one image and layer")
        config = archive.extractfile(manifest[0]["Config"]).read()
        layer = archive.extractfile(manifest[0]["Layers"][0]).read()
    if hashlib.sha256(config).hexdigest() != CONFIG or hashlib.sha256(layer).hexdigest() != LAYER:
        raise ValueError("fixture config/layer digest mismatch")
    files = {
        "config.json": config,
        "layer.tar.gz": layer,
        "manifest.json": json.dumps([{
            "Config": "config.json", "Layers": ["layer.tar.gz"],
            "RepoTags": ["ghcr.io/aquasecurity/trivy-test-images:alpine-39"],
        }], sort_keys=True, separators=(",", ":")).encode(),
    }
    with tarfile.open(target, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            header = tarfile.TarInfo(name)
            header.size, header.mode = len(data), 0o600
            archive.addfile(header, io.BytesIO(data))


def main():
    FIXTURES.mkdir(exist_ok=True)
    subprocess.run(["docker", "pull", "--platform", "linux/amd64", IMAGE], check=True)
    raw = FIXTURES / "docker-export.tar"
    subprocess.run(["docker", "image", "save", "--platform", "linux/amd64", "--output", str(raw), IMAGE], check=True)
    canonical_archive(raw, FIXTURES / "alpine-39.tar")
    raw.unlink()
    module = json.loads(subprocess.check_output(["go", "list", "-m", "-json", "github.com/aquasecurity/trivy"], cwd=ROOT / "tools/local-scanner"))
    if module["Version"] != "v0.75.0":
        raise ValueError("fixture preparation requires pinned Trivy v0.75.0")
    source = Path(module["Dir"]) / "integration/testdata/fixtures/db"
    destination = FIXTURES / "db-source"
    destination.mkdir(exist_ok=True)
    for name, digest in DB_SOURCES.items():
        if hashlib.sha256((source / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"{name}: upstream fixture digest mismatch")
        shutil.copyfile(source / name, destination / name)
    subprocess.run(["go", "run", "./cmd/prepare-db", str(FIXTURES)], cwd=ROOT / "tools/local-scanner", check=True)
    shutil.copyfile(FIXTURES / "alpine-39.tar", FIXTURES / "runtime/image.tar")
    debian = Path(module["Dir"]) / "pkg/fanal/test/testdata/vuln-image.tar.gz"
    if hashlib.sha256(debian.read_bytes()).hexdigest() != "60d91170eedb6f4af94899684b500338a84f10d643f2761e6a4821959d0c9e3a":
        raise ValueError("Debian archive digest mismatch")
    shutil.copytree(FIXTURES / "runtime", FIXTURES / "debian-runtime", dirs_exist_ok=True)
    shutil.copyfile(debian, FIXTURES / "debian-runtime/image.tar")
    for name in ["alpine-39.tar", "runtime/db/trivy.db", "runtime/db/metadata.json"]:
        path = FIXTURES / name
        print(f"{name}: {path.stat().st_size} bytes, sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
