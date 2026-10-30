"""Tests for observability (P2.3 - OpenTelemetry)."""
from __future__ import annotations

from clca.observability import (
    SpanAttrs,
    create_span,
    get_meter,
    get_tracer,
    init_observability,
    set_span_status,
)


def test_init_observability_no_endpoint():
    """init_observability without OTLP endpoint should not crash."""
    init_observability(service_name="test-service", service_version="0.1.0")
    assert get_tracer() is not None
    assert get_meter() is not None


def test_create_span_and_status():
    """Creating a span and setting status should work."""
    init_observability()
    tracer = get_tracer()
    with tracer.start_as_current_span("test.span") as span:
        span.set_attribute(SpanAttrs.RUN_ID, "run-123")
        span.set_attribute(SpanAttrs.DECISION, "PASS")
        set_span_status(span, "ok")


def test_create_span_error_status():
    """Error status should be settable."""
    init_observability()
    tracer = get_tracer()
    with tracer.start_as_current_span("test.error") as span:
        set_span_status(span, "error", "something went wrong")


def test_create_span_helper():
    """create_span helper should return a span."""
    init_observability()
    span = create_span("helper.span", {SpanAttrs.RUN_ID: "run-456"})
    assert span is not None
    span.set_attribute(SpanAttrs.SCENARIO_ID, "safe_code_change")
    span.end()


def test_meter_creates_counter():
    """Meter should be able to create counters."""
    init_observability()
    meter = get_meter()
    counter = meter.create_counter("clca.runs.total", description="Total runs")
    counter.add(1, {"scenario.id": "safe_code_change"})


def test_meter_creates_histogram():
    """Meter should be able to create histograms."""
    init_observability()
    meter = get_meter()
    histogram = meter.create_histogram("clca.run.duration_ms", description="Run duration")
    histogram.record(1500, {"scenario.id": "write_tool_escalation"})


def test_init_idempotent():
    """Calling init twice should not crash."""
    init_observability()
    init_observability()
    assert get_tracer() is not None
    assert get_meter() is not None
