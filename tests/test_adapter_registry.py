"""Tests for the adapter registry."""
from __future__ import annotations

from pathlib import Path

from clca.adapters.base import Adapter, AdapterResult, relationship_id
from clca.adapters.registry import AdapterRegistry
from clca.intake import ChangeManifest


class _DummyAdapter(Adapter):
    name = "dummy"

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        return AdapterResult(
            assets=[],
            relationships=[],
            evidence=[],
            gaps=[],
        )


def test_registry_register_and_get():
    reg = AdapterRegistry()
    reg.register("dummy", _DummyAdapter())
    assert reg.get("dummy") is not None
    assert reg.names() == ["dummy"]


def test_registry_collect_returns_empty_for_known_adapter():
    reg = AdapterRegistry()
    reg.register("dummy", _DummyAdapter())
    manifest = ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("src/foo.py",),
    )
    result = reg.collect("dummy", Path("/tmp/repo"), manifest)
    assert result.assets == []
    assert result.gaps == []


def test_registry_unknown_adapter_returns_gap():
    reg = AdapterRegistry()
    manifest = ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("src/foo.py",),
    )
    result = reg.collect("nonexistent", Path("/tmp/repo"), manifest)
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == "unsupported_asset"
    assert "nonexistent" in result.gaps[0].why_it_matters


def test_registry_collect_all_merges():
    reg = AdapterRegistry()
    reg.register("dummy", _DummyAdapter())
    manifest = ChangeManifest(
        repository="demo/repo",
        base_revision="a" * 40,
        head_revision="b" * 40,
        diff_digest="sha256:deadbeef",
        changed_paths=("src/foo.py",),
    )
    result = reg.collect_all(Path("/tmp/repo"), manifest)
    assert result.gaps == []


def test_relationship_id_is_deterministic():
    rid1 = relationship_id("asset:a", "asset:b", "calls")
    rid2 = relationship_id("asset:a", "asset:b", "calls")
    rid3 = relationship_id("asset:b", "asset:a", "calls")
    assert rid1 == rid2
    assert rid1 != rid3
    assert rid1.startswith("rel:")
