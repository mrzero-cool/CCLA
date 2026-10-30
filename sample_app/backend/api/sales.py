"""Synthetic API handler; intentionally framework-neutral for the starter."""
from backend.services.pricing import net_sales


def create_sales_response(payload: dict) -> dict:
    required = {"customer_id", "unit_price", "quantity"}
    missing = sorted(required - payload.keys())
    if missing:
        raise ValueError(f"missing fields: {', '.join(missing)}")
    return {
        "customer_id": payload["customer_id"],
        "net_sales": net_sales(
            float(payload["unit_price"]),
            int(payload["quantity"]),
            float(payload.get("discount_rate", 0.0)),
        ),
    }
