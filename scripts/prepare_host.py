#!/usr/bin/env python3
"""Prepare the exact host source used by the SDK and sandbox proof."""
import argparse
from pathlib import Path
import re
import subprocess

HOST_REVISION = "b1f430b3d2ee1ce2d8a08bd323865861b6ef9d14"
ROOT = Path(__file__).resolve().parents[1]


def head(target):
    return subprocess.check_output(["git", "-C", str(target), "rev-parse", "HEAD"], text=True).strip()


def prepare(source, target, revision=HOST_REVISION):
    target = Path(target)
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("host revision must be a full commit hash")
    if target.exists():
        if head(target) != revision:
            raise ValueError(f"{target} is at a different revision; preserve it and use another destination")
        for args in (["diff", "--quiet", "HEAD", "--"], ["diff", "--quiet", "--cached", "--"]):
            result = subprocess.run(["git", "-C", str(target), *args])
            if result.returncode:
                raise ValueError(f"{target} has modified tracked source; preserve it and use another destination")
        extra_sdk = subprocess.check_output(["git", "-C", str(target), "ls-files", "--others", "--", "sdk/go"])
        if extra_sdk:
            raise ValueError(f"{target} has untracked SDK files; preserve them and use another destination")
        return
    subprocess.run(["git", "clone", "--no-checkout", source, str(target)], check=True)
    subprocess.run(["git", "-C", str(target), "checkout", "--detach", revision], check=True)
    if head(target) != revision:
        raise ValueError("host checkout does not match the required revision")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="https://github.com/srelens/srelens.git")
    parser.add_argument("--target", type=Path, default=ROOT / ".host-v0.2")
    args = parser.parse_args()
    prepare(args.source, args.target)
    print(f"host source: {head(args.target)}")


if __name__ == "__main__":
    main()
