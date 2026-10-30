# Benchmark starter

`scenarios/scenarios.json` defines 48 proposed controlled cases. `validate_manifest.py` validates IDs, required fields, total count and family distribution.

This is **scenario design**, not yet a completed comparative benchmark runner. Implement execution next so each scenario runs against baseline full-suite, native selector, selected existing tool, CLCA static-only and CLCA integrated modes where supported. Persist one JSONL result per scenario/mode, raw check outputs, oracle status and limitations. Do not hard-code expected results into the analyzer input; keep labels available only to the evaluator.

Run validation and inspect the current planner against the target check-selection contract:

```bash
python benchmark/validate_manifest.py
python benchmark/compare_planner_to_manifest.py
# Once every target selection is reconciled, make mismatches fail CI:
python benchmark/compare_planner_to_manifest.py --strict
```

`compare_planner_to_manifest.py` is deliberately labelled a **planner diagnostic**, not a regression benchmark. It compares `expected_mandatory_checks` with the current catalog-driven plan and emits machine-readable JSON. In the v0.4 audit snapshot, 40/48 selections align and 8 need review (see `results/planner_alignment_v0.4.json`). The mismatches are left visible rather than silently rewriting the expected benchmark contract to match the implementation. It does not mutate seeded faults, execute tests, or support any claim about bug-detection rates or time saved.
