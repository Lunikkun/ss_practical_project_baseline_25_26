import uuid

from test_utils import _find_document_id, _login, _upload_document, _url, _wait_for_service


def test_idor_attack_tree_sequential_id_tampering_is_blocked():
    """
    Scenario 6 (Attack Tree): an authenticated attacker tries ID predictability
    and URL tampering. Expected defense: uniform 404 for unauthorized resources
    without existence leakage.
    """
    _wait_for_service()

    unique_title = f"scenario6-seq-{uuid.uuid4().hex[:8]}"
    alice = _login("alice", "tth1mJj5?£58")
    _upload_document(alice, unique_title, "scenario6.txt", b"private-s6")
    owned_document_id = _find_document_id(alice, unique_title)

    bob = _login("bob", "De586:Iq6}?!")

    candidate_ids = {
        owned_document_id - 1,
        owned_document_id,
        owned_document_id + 1,
        owned_document_id + 2,
    }

    for candidate_id in candidate_ids:
        if candidate_id <= 0:
            continue

        details_response = bob.get(_url(f"/documents/{candidate_id}"), timeout=10)
        download_response = bob.get(_url(f"/documents/{candidate_id}/download"), timeout=10)

        assert details_response.status_code == 404, (
            f"Expected 404 on details tampering for id={candidate_id}, got {details_response.status_code}"
        )
        assert download_response.status_code == 404, (
            f"Expected 404 on download tampering for id={candidate_id}, got {download_response.status_code}"
        )


def test_idor_attack_tree_shared_endpoint_requires_explicit_share():
    """
    Scenario 6: replay against /shared/<id>/download without active share.
    Expected defense: uniform 404 (no difference between 'not found' and
    'not authorized').
    """
    _wait_for_service()

    unique_title = f"scenario6-shared-{uuid.uuid4().hex[:8]}"
    alice = _login("alice", "tth1mJj5?£58")
    _upload_document(alice, unique_title, "scenario6-shared.txt", b"private-shared")
    document_id = _find_document_id(alice, unique_title)

    bob = _login("bob", "De586:Iq6}?!")

    response = bob.get(_url(f"/shared/{document_id}/download"), timeout=10)
    assert response.status_code == 404, (
        f"Expected 404 for non-shared document on /shared endpoint, got {response.status_code}"
    )
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert "default-src 'self'" in response.headers.get("Content-Security-Policy", "")
