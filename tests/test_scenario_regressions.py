"""Scenario-level regression tests; these are pipeline self-consistency checks."""
from clca.scenarios import run_scenario


def test_prompt_behavior_regression_is_caught_by_required_behavior_suite():
    result = run_scenario("prompt_behavior_regression", budget_seconds=60)
    assert result.decision == "BLOCK", result.reasons
    behavior = next(c for c in result.checks if c["check_id"] == "agent-behavior-evals")
    assert behavior["status"] == "failed"
    assert any("agent-behavior-evals" in reason for reason in result.reasons)
