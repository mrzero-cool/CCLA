"""SBOM (Software Bill of Materials) generator for CLCA (P2.5).

Generates an SPDX 2.3-compatible SBOM documenting all Python package
dependencies, their versions, licenses, and download locations.  This is
required for supply chain security and compliance per roadmap section 8.

Usage:
    python -m scripts.sbom --output sbom.spdx.json
    python -m scripts.sbom --output sbom.spdx.json --format cyclonedx
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_installed_packages() -> list[dict[str, Any]]:
    """Get all installed Python packages with versions and licenses."""
    try:
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            check=True,
        )
        packages = json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return []

    # Enrich with license info where available
    enriched = []
    for pkg in packages:
        name = pkg["name"]
        version = pkg["version"]
        # Try to get license from metadata
        license_expr = "NOASSERTION"
        try:
            result = subprocess.run(
                ["pip", "show", name],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in result.stdout.splitlines():
                if line.startswith("License:"):
                    license_expr = line.split(":", 1)[1].strip()
                    break
        except (subprocess.CalledProcessError, OSError):
            pass

        enriched.append(
            {
                "name": name,
                "version": version,
                "license": license_expr,
            }
        )

    return enriched


def generate_spdx(packages: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate SPDX 2.3 SBOM document."""
    now = _utc_now()

    packages_spdx = []
    for idx, pkg in enumerate(packages, start=1):
        packages_spdx.append(
            {
                "SPDXID": f"SPDXRef-Package-{idx}",
                "SPDXVersion": "SPDX-2.3",
                "PackageName": pkg["name"],
                "PackageVersion": pkg["version"],
                "PackageDownloadLocation": "NOASSERTION",
                "FilesAnalyzed": False,
                "LicenseConcluded": pkg["license"],
                "LicenseInfoInFiles": [pkg["license"]],
                "PackageSupplier": "NOASSERTION",
                "PackageOriginator": "NOASSERTION",
            }
        )

    sbom = {
        "SPDXVersion": "SPDX-2.3",
        "DataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "DocumentName": "clca-mvp",
        "DocumentNamespace": f"https://clca.dev/sbom/{_utc_now()}",
        "Creator": [
            "Tool: clca-sbom-generator",
            f"ToolVersion: 0.4.0",
            f"Created: {now}",
        ],
        "Created": now,
        "Packages": packages_spdx,
        "PackageCount": len(packages_spdx),
        "Relationships": [],
    }
    return sbom


def generate_cyclonedx(packages: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate CycloneDX 1.4 SBOM document."""
    now = _utc_now()

    components = []
    for idx, pkg in enumerate(packages, start=1):
        components.append(
            {
                "type": "library",
                "bom-ref": f"pkg:{pkg['name']}@{pkg['version']}",
                "name": pkg["name"],
                "version": pkg["version"],
                "licenses": [
                    {"license": {"id": pkg["license"] if pkg["license"] else "NOASSERTION"}}
                ],
            }
        )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:clca-sbom-{_utc_now()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"name": "clca-sbom-generator", "version": "0.4.0"}],
        },
        "components": components,
    }
    return sbom


def main() -> int:
    parser = argparse.ArgumentParser(description="CLCA SBOM generator (P2.5)")
    parser.add_argument(
        "--output",
        default="sbom.spdx.json",
        help="Output file path for the SBOM",
    )
    parser.add_argument(
        "--format",
        choices=["spdx", "cyclonedx"],
        default="spdx",
        help="SBOM format to generate",
    )
    args = parser.parse_args()

    packages = get_installed_packages()

    if args.format == "spdx":
        sbom = generate_spdx(packages)
    else:
        sbom = generate_cyclonedx(packages)

    output_path = Path(args.output)
    output_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    print(f"SBOM generated: {output_path}")
    print(f"  Format: {args.format}")
    print(f"  Packages: {len(packages)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
