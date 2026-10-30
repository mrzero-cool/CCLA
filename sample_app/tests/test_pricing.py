import pytest
from backend.services.pricing import net_sales


def test_net_sales_applies_discount():
    assert net_sales(10.0, 3, 0.2) == pytest.approx(24.0)


def test_quantity_cannot_be_negative():
    with pytest.raises(ValueError):
        net_sales(10.0, -1)
