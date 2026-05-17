import io
import os
import uuid

import pytest

from test_utils import _get_csrf_token, _login, _url, _wait_for_service


UPLOAD_RATE_LIMIT = int(os.getenv("UPLOAD_RATE_LIMIT", "25"))


def test_storage_dos_attack_tree_upload_flood_triggers_rate_limit():
    """
    Scenario 11: upload flood to exhaust resources.
    Expected defense: per-user throttling with 429 responses.
    """
    _wait_for_service()

    if UPLOAD_RATE_LIMIT > 60:
        pytest.skip("UPLOAD_RATE_LIMIT too high for deterministic flood test runtime")

    alice = _login("alice", "tth1mJj5?£58")

    blocked_response = None
    for i in range(UPLOAD_RATE_LIMIT + 5):
        csrf_token = _get_csrf_token(alice, _url("/documents"))
        title = f"scenario11-flood-{uuid.uuid4().hex[:8]}-{i}"
        response = alice.post(
            _url("/documents/upload"),
            data={"title": title, "csrf_token": csrf_token},
            files={"document": (f"flood-{i}.txt", io.BytesIO(b"x"), "text/plain")},
            allow_redirects=False,
            timeout=10,
        )
        if response.status_code == 429:
            blocked_response = response
            break

    assert blocked_response is not None, "Expected upload throttling (429) under flood conditions"
    assert (
        "Too many upload requests" in blocked_response.text
        or "Upload quota exceeded" in blocked_response.text
    )
    assert blocked_response.headers.get("X-Frame-Options") == "DENY"
    assert blocked_response.headers.get("X-Content-Type-Options") == "nosniff"


def test_storage_dos_attack_tree_quota_controls_present_regression():
    """
    Static regression: verify anti-storage-exhaustion controls are present.
    """
    with open("web/app/app.py", "r", encoding="utf-8") as f:
        source = f.read()

    required_markers = [
        "UPLOAD_RATE_LIMIT",
        "USER_MAX_FILES",
        "USER_STORAGE_QUOTA_BYTES",
        "GLOBAL_STORAGE_QUOTA_BYTES",
        "MIN_FREE_DISK_BYTES",
        "get_total_storage_usage_bytes",
        "get_user_storage_usage_bytes",
    ]
    for marker in required_markers:
        assert marker in source
