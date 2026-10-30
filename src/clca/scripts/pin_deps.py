"""Pinned dependency generator for CLCA supply chain security (P2.5).

Generates a requirements.lock file with pinned versions and SHA256 hashes
for reproducible, verified installs.

Usage:
    python -m scripts.pin_deps --output requirements.lock
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path
from typing import Any


def get_installed_packages_with_hashes() -> list[dict[str, str]]:
    """Get installed packages with pip show to find their hashes."""
    # pip list --format=json gives name and version
    result = subprocess.run(
        ["pip", "list", "--format=json"],
        capture_output=True,
        text=True,
        check=True,
    )
    packages = json.loads(result.stdout)

    pinned = []
    for pkg in packages:
        name = pkg["name"]
        version = pkg["version"]

        # Get the hash from pip show or pip download
        # We use pip download --no-deps to get the file, then hash it
        try:
            result = subprocess.run(
                ["pip", "download", "--no-deps", "--no-binary", ":all:",
                 f"{name}=={version}", "--no-build-isolation"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            if result.returncode == 0:
                # Parse the downloaded file path from output
                for line in result.stdout.splitlines():
                    if "Saved:" in line:
                        filepath = line.split("Saved:", 1)[1].strip()
                        with open(filepath, "rb") as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                        pinned.append({
                            "name": name,
                            "version": version,
                            "hash": f"sha256:{file_hash}",
                        })
                        break
        except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
            pass

        # If we couldn't get a hash, still include with just version
        if not any(p["name"] == name for p in pinned):
            pinned.append({
                "name": name,
                "version": version,
                "hash": "UNKNOWN",
            })

    return pinned


def main() -> int:
    parser = argparse.ArgumentParser(description="CLCA pinned dependency generator")
    parser.add_argument(
        "--output",
        default="requirements.lock",
        help="Output file path for pinned requirements",
    )
    args = parser.parse_args()

    packages = get_installed_packages_with_hashes()

    lines = ["# CLCA pinned dependencies (P2.5 supply chain)"]
    lines.append(f"# Generated: {__import__('datetime').datetime.now().isoformat()}")
    lines.append("# Format: package==version # sha256:<hash>")
    lines.append("")

    for pkg in packages:
        name = pkg["name"]
        version = pkg["version"]
        pkg_hash = pkg["hash"]
        lines.append(f"{name}=={version}  # {pkg_hash}")

    output_path = Path(args.output)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Pinned requirements written to {output_path}")
    print(f"  Packages: {len(packages)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
