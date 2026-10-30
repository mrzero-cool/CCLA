"""Outbound integrations (GitHub today; GitLab/Azure DevOps are TODOs)."""
from .github import (  # noqa: F401
    CONCLUSION,
    GitHubError,
    build_check_run_payload,
    parse_pull_request_event,
    post_check_run,
    scenario_for_paths,
    sign_payload,
    verify_webhook_signature,
)

__all__ = [
    "CONCLUSION",
    "GitHubError",
    "build_check_run_payload",
    "parse_pull_request_event",
    "post_check_run",
    "scenario_for_paths",
    "sign_payload",
    "verify_webhook_signature",
]
