"""Tests for CLCA supply chain tooling (P2.5 - SBOM generation)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clca.scripts.sbom import generate_spdx, generate_cyclonedx, get_installed_packages


def test_get_installed_packages_returns_list():
    packages = get_installed_packages()
    assert isinstance(packages, list)
    # Should have at least some packages
    assert len(packages) > 0
    # Each package should have name and version
    for pkg in packages:
        assert "name" in pkg
        assert "version" in pkg
        assert "license" in pkg


def test_generate_spdx_structure():
    packages = [
        {"name": "clca", "version": "0.4.0", "license": "MIT"},
        {"name": "pydantic", "version": "2.13.5", "license": "MIT"},
    ]
    sbom = generate_spdx(packages)

    assert sbom["SPDXVersion"] == "SPDX-2.3"
    assert sbom["DocumentName"] == "clca-mvp"
    assert "SPDXID" in sbom
    assert "Creator" in sbom
    assert "Created" in sbom
    assert len(sbom["Packages"]) == 2
    assert sbom["PackageCount"] == 2
    assert sbom["Packages"][0]["PackageName"] == "clca"
    assert sbom["Packages"][0]["PackageVersion"] == "0.4.0"


def test_generate_cyclonedx_structure():
    packages = [
        {"name": "clca", "version": "0.4.0", "license": "MIT"},
    ]
    sbom = generate_cyclonedx(packages)

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.4"
    assert len(sbom["components"]) == 1
    assert sbom["components"][0]["name"] == "clca"
    assert sbom["components"][0]["version"] == "0.4.0"


def test_sbom_file_output(tmp_path):
    from clca.scripts.sbom import main

    output_path = tmp_path / "sbom.spdx.json"
    # We can't easily test main() with argparse, but we can test the generation
    packages = get_installed_packages()
    sbom = generate_spdx(packages)
    output_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    assert output_path.is_file()
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["SPDXVersion"] == "SPDX-2.3"
    assert data["PackageCount"] > 0


def test_cyclonedx_file_output(tmp_path):
    from clca.scripts.sbom import generate_cyclonedx

    output_path = tmp_path / "sbom.cyclonedx.json"
    packages = get_installed_packages()
    sbom = generate_cyclonedx(packages)
    output_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    assert output_path.is_file()
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.4"
    assert len(data["components"]) > 0
