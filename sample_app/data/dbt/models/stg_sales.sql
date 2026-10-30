-- Synthetic dbt-style model for the benchmark. This is illustrative SQL.
select
    customer_id,
    unit_price,
    quantity,
    discount_rate,
    unit_price * quantity * (1 - discount_rate) as net_sales
from raw_sales
