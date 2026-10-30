"""Synthetic retail pricing logic used by the CLCA demo benchmark."""


def net_sales(unit_price: float, quantity: int, discount_rate: float = 0.0) -> float:
    if quantity < 0:
        raise ValueError("quantity must be non-negative")
    if not 0.0 <= discount_rate <= 1.0:
        raise ValueError("discount_rate must be between 0 and 1")
    return unit_price * quantity * (1.0 - discount_rate)
