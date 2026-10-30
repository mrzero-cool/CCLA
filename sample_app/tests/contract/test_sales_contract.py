"""Contract check: dbt model columns must satisfy the declared sales contract."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((ROOT / "data" / "contracts" / "sales_contract.json").read_text(encoding="utf-8"))
MANIFEST = json.loads((ROOT / "data" / "dbt" / "manifest.json").read_text(encoding="utf-8"))


def test_model_columns_satisfy_contract():
    model = MANIFEST["nodes"]["model.retail.stg_sales"]
    model_columns = set(model["columns"])
    required = set(CONTRACT["required_columns"])
    missing = required - model_columns
    assert not missing, f"model is missing contract columns: {sorted(missing)}"


def test_contract_invariants_are_declared():
    assert CONTRACT["invariants"], "contract must declare invariants"


def test_source_columns_cover_upstream_inputs():
    source = MANIFEST["sources"]["source.retail.raw_sales"]
    upstream = set(source["columns"])
    expected = {"customer_id", "unit_price", "quantity", "discount_rate"}
    assert expected <= upstream, f"source is missing columns: {sorted(expected - upstream)}"
