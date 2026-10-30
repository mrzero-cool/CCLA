# CLCA Interactive Demo (for judges)

Self-contained demo that lets judges play with mock CLCA scenarios without
needing the running service. Opens in any browser — no build step.

## Files

| File | Purpose |
|---|---|
| `demo/mock_data.py` | Generates synthetic repo snapshots + expected decisions |
| `demo/mock_data/*.json` | Per-scenario bundles, linked-tool outputs, decisions |
| `demo/interactive_demo.html` | Judge-facing interactive UI (open directly in browser) |
| `docs/PRODUCTION_READINESS_GAP_ANALYSIS.md` | Full production gap analysis |
| `docs/LINKED_TOOLS_CATALOG.md` | All external tools CLCA integrates (graphify, axiom graph, etc.) |

## How to use

1. Generate mock data:
   ```powershell
   $env:PYTHONPATH="src"; python demo/mock_data.py
   ```
2. Open `demo/interactive_demo.html` in a browser.
3. Click any scenario to "run" it — see the decision banner, impact graph,
   evidence cards, and linked-tool outputs side by side.
4. Toggle the policy switch to see how decisions change when rules are
   tightened or relaxed.

No server, no secrets, no network required.