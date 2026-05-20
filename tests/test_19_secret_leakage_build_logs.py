from pathlib import Path

from test_utils import _wait_for_service

def test_secret_leakage_workflows_use_log_redaction_on_failure():

    _wait_for_service()

    delivery = Path(".github/workflows/2-delivery.yml").read_text(encoding="utf-8")
    deploy = Path(".github/workflows/3-deploy.yml").read_text(encoding="utf-8")

    assert "logs --no-color --tail 300 | .github/scripts/redact_ci_logs.sh" in delivery
    assert "logs --no-color --tail 300 | .github/scripts/redact_ci_logs.sh" in deploy

def test_secret_leakage_redaction_script_masks_common_patterns():

    script = Path(".github/scripts/redact_ci_logs.sh").read_text(encoding="utf-8")

    expected_markers = [
        "***REDACTED***",
        "[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]",
        "[Ss][Ee][Cc][Rr][Ee][Tt]",
        "[Tt][Oo][Kk][Ee][Nn]",
        "postgres(ql)?://",
    ]
    for marker in expected_markers:
        assert marker in script

def test_secret_leakage_workflows_avoid_plaintext_debug_commands():

    workflow_files = [
        Path(".github/workflows/1-integration.yml"),
        Path(".github/workflows/2-delivery.yml"),
        Path(".github/workflows/3-deploy.yml"),
    ]
    dangerous_commands = ["printenv", "set -x"]

    for wf in workflow_files:
        content = wf.read_text(encoding="utf-8")
        for command in dangerous_commands:
            assert command not in content, f"Found dangerous debug command '{command}' in {wf}"