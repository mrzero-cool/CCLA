# Synthetic sample application

This is a small, fictional retail analytics workflow for CLCA demos. It contains a Python pricing helper/API shape, a dbt-style SQL model, a data contract, a business metric definition, and an agent prompt/tool manifest. It is not a Tredence internal application and does not contain real customer data.

The current `stg_sales.sql` is illustrative. Before using dbt manifest ingestion in a live demo, add a real `dbt_project.yml`, source definitions and generated `manifest.json`, or load the separately generated fixture into the adapter.
