"""Adapter registry: discovers, registers, and dispatches to external tool adapters.

Every external graph/lineage/security tool (AxiomCode, Enola, Code System Graph,
DataHub, OpenLineage, OWASP harness, Praxen, Stryker, etc.) is represented as an
Adapter that implements the common collect() contract.  The registry is the single
point through which the planner and policy engine ask "what does tool X know about
this change?".
"""
from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any

from .base import Adapter, AdapterResult, relationship_id
from ..digest import digest_obj
from ..intake import ChangeManifest
from ..models import CoverageGap

logger = logging.getLogger("clca.adapters.registry")


class AdapterRegistry:
    """Maps adapter names to adapter instances and dispatches collection.

    Adapters are registered by name (e.g. "axiomcodegraph", "enola",
    "code_system_graph", "datahub", "openlineage", "owasp_agent_security",
    "praxen", "stryker").  Unknown adapters return an empty result with a
    coverage gap so the planner can decide whether to treat missing data as
    INCOMPLETE or proceed with reduced confidence.
    """

    def __init__(self) -> None:
        self._adapters: dict[str, Adapter] = {}
        self._failures: dict[str, str] = {}

    def register(self, name: str, adapter: Adapter) -> None:
        self._adapters[name] = adapter
        self._failures.pop(name, None)
        logger.info("registered adapter %s -> %s", name, adapter.__class__.__name__)

    def register_failure(self, name: str, reason: str) -> None:
        """Record that an adapter could not be loaded (missing dep, bad config)."""
        self._failures[name] = reason
        logger.warning("adapter %s unavailable: %s", name, reason)

    def get(self, name: str) -> Adapter | None:
        return self._adapters.get(name)

    def names(self) -> list[str]:
        return sorted(self._adapters.keys())

    def unavailable(self) -> dict[str, str]:
        return dict(self._failures)

    def collect(
        self,
        name: str,
        repo: Path,
        manifest: ChangeManifest,
    ) -> AdapterResult:
        """Run one adapter by name.  Missing adapters yield a gap, not a crash."""
        adapter = self._adapters.get(name)
        if adapter is None:
            reason = self._failures.get(name, "adapter not registered")
            return AdapterResult(
                gaps=[
                    CoverageGap(
                        gap_id=f"gap:adapter:{name}",
                        kind="unsupported_asset",
                        severity="medium",
                        subject_refs=[manifest.head_revision],
                        why_it_matters=f"Adapter '{name}' is not available: {reason}",
                        blocking=False,
                        required=False,
                        remediation=f"Install or configure the '{name}' adapter.",
                    )
                ]
            )
        try:
            return adapter.collect(repo, manifest)
        except Exception as exc:  # noqa: BLE001 — adapter failures are isolated
            logger.exception("adapter %s raised during collect", name)
            return AdapterResult(
                gaps=[
                    CoverageGap(
                        gap_id=f"gap:adapter:{name}:error",
                        kind="runner_unavailable",
                        severity="high",
                        subject_refs=[manifest.head_revision],
                        why_it_matters=f"Adapter '{name}' failed: {exc!s}",
                        blocking=False,
                        required=False,
                        remediation=f"Fix or bypass the '{name}' adapter.",
                    )
                ]
            )

    def collect_all(
        self,
        repo: Path,
        manifest: ChangeManifest,
        names: list[str] | None = None,
    ) -> AdapterResult:
        """Run every enabled adapter (or a subset) and merge results."""
        target = names if names is not None else self.names()
        merged = AdapterResult()
        for name in target:
            result = self.collect(name, repo, manifest)
            merged.extend(result)
        return merged


# Module-level default registry so the CLI and service can share one instance.
default_registry = AdapterRegistry()


def get_default_registry() -> AdapterRegistry:
    return default_registry
