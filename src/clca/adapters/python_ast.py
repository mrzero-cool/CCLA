"""Native Python AST adapter.

Extracts functions, classes and API handlers, resolves intra-repository calls and
imports, and records unresolved dynamic references as coverage gaps instead of
dropping them (architecture section 2: adapters must not hide ambiguity).
"""
from __future__ import annotations

import ast
from pathlib import Path

from ..digest import digest_text, iter_files
from ..intake import ChangeManifest
from ..models import Asset, CoverageGap, Relationship
from .base import AdapterResult, make_evidence, relationship_id

_API_HINTS = ("backend/api/", "app/routes/", "api/")
_DYNAMIC_IDS = {"getattr", "eval", "exec", "__import__"}


class PythonASTAdapter:
    name = "python-ast"

    def collect(self, repo: Path, manifest: ChangeManifest) -> AdapterResult:
        result = AdapterResult()
        symbols: dict[str, Asset] = {}  # "module:qualname" -> asset
        by_module: dict[str, list[str]] = {}
        calls: list[tuple[str, str]] = []  # (caller_id, called_name)
        imports: list[tuple[str, str]] = []  # (caller_id, imported_module)

        py_files = [p for p in iter_files(repo) if p.suffix == ".py"]
        for path in py_files:
            rel = path.relative_to(repo).as_posix()
            module = rel[:-3].replace("/", ".").removesuffix(".__init__")
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=rel)
            except (SyntaxError, UnicodeDecodeError) as exc:
                result.gaps.append(CoverageGap(
                    gap_id=f"gap-ast-parse:{rel}",
                    kind="unsupported_asset",
                    severity="medium",
                    subject_refs=[rel],
                    why_it_matters=f"Python file could not be parsed ({exc.__class__.__name__}); its impact is unknown.",
                    remediation="Fix the syntax error or exclude the path with a recorded reason.",
                ))
                continue

            # Register container symbols (functions and classes) with line ranges.
            containers: list[tuple[str, int, int]] = []  # (asset_id, start, end)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    kind = (
                        "api.endpoint"
                        if rel.startswith(_API_HINTS) and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        else ("code.class" if isinstance(node, ast.ClassDef) else "code.function")
                    )
                    asset_id = f"py:{module}:{node.name}"
                    asset = Asset(
                        asset_id=asset_id, kind=kind, name=node.name, path=rel,
                        revision=manifest.head_revision,
                        criticality="high" if kind == "api.endpoint" else "medium",
                        attributes={"module": module, "line": node.lineno},
                    )
                    symbols[f"{module}:{node.name}"] = asset
                    by_module.setdefault(module, []).append(asset_id)
                    result.assets.append(asset)
                    containers.append((asset_id, node.lineno, node.end_lineno or node.lineno))
                    result.relationships.append(Relationship(
                        relationship_id=relationship_id(f"py-module:{module}", asset_id, "owns"),
                        source_asset_id=f"py-module:{module}", target_asset_id=asset_id,
                        relation_type="owns", impact_direction="forward",
                        resolution="resolved", observed_revision=manifest.head_revision,
                    ))

            for node in ast.walk(tree):
                owner = self._owner(containers, getattr(node, "lineno", 0))
                if owner is None:
                    continue
                if isinstance(node, ast.Call):
                    name = self._call_name(node.func)
                    if name:
                        calls.append((owner, name))
                    if isinstance(node.func, ast.Name) and node.func.id in _DYNAMIC_IDS:
                        result.gaps.append(CoverageGap(
                            gap_id=f"gap-dynamic-dispatch:{owner}:{node.lineno}",
                            kind="unresolved_dependency",
                            severity="high",
                            subject_refs=[owner],
                            why_it_matters="Dynamic dispatch/reflection hides a real call target from static impact analysis.",
                            blocking=True,
                            required=True,
                            remediation="Declare the call target statically or accept the promoted full-suite fallback.",
                        ))
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        imports.append((owner, alias.name))

        repo_modules = set(by_module)
        for caller, name in calls:
            for module, ids in by_module.items():
                for target in ids:
                    if target.rsplit(":", 1)[-1] == name and target != caller:
                        result.relationships.append(Relationship(
                            relationship_id=relationship_id(caller, target, "calls"),
                            source_asset_id=caller, target_asset_id=target,
                            relation_type="calls", impact_direction="forward",
                            resolution="resolved", observed_revision=manifest.head_revision,
                        ))

        for caller, module in imports:
            matched = sorted({
                mod for mod in repo_modules
                if module == mod or module.startswith(mod + ".") or mod.startswith(module + ".")
            })
            for mod in matched:
                result.relationships.append(Relationship(
                    relationship_id=relationship_id(caller, f"py-module:{mod}", "imports"),
                    source_asset_id=caller, target_asset_id=f"py-module:{mod}",
                    relation_type="imports", impact_direction="forward",
                    resolution="inferred", observed_revision=manifest.head_revision,
                    limitations=["Import edges are module-level; call edges are resolved separately by name."],
                ))

        if symbols:
            result.evidence.append(make_evidence(
                self.name, "python_ast_index", sorted(symbols),
                manifest.head_revision, digest_text("\n".join(sorted(symbols))),
            ))
        result.facts["python_symbols"] = sorted(symbols)
        return result

    @staticmethod
    def _owner(containers: list[tuple[str, int, int]], lineno: int) -> str | None:
        """Innermost enclosing top-level container for a line, if any."""
        best: str | None = None
        best_span: tuple[int, int] | None = None
        for asset_id, start, end in containers:
            if start <= lineno <= end and (best_span is None or (end - start) < (best_span[1] - best_span[0])):
                best, best_span = asset_id, (start, end)
        return best

    @staticmethod
    def _call_name(func: ast.expr) -> str | None:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None
