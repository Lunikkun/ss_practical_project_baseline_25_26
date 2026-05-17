import uuid

from test_utils import (
    _find_document_id,
    _find_user_id_from_share_form,
    _get_csrf_token,
    _login,
    _upload_document,
    _url,
    _wait_for_service,
)


def test_revocation_immediate_effect_with_active_session():
    """
    Scenario 7: a former reviewer keeps an active session but loses access.
    After revoke, access must be blocked immediately on all document endpoints.
    """
    _wait_for_service()

    unique_title = f"scenario7-revoke-{uuid.uuid4().hex[:8]}"
    content = b"scenario7 private content"

    alice = _login("alice", "tth1mJj5?£58")
    _upload_document(alice, unique_title, "scenario7.txt", content)
    document_id = _find_document_id(alice, unique_title)

    bob_id = _find_user_id_from_share_form(alice, document_id, "bob")

    csrf_token = _get_csrf_token(alice, _url(f"/documents/{document_id}"))
    share_response = alice.post(
        _url(f"/documents/{document_id}/share"),
        data={"shared_with": str(bob_id), "csrf_token": csrf_token},
        allow_redirects=False,
        timeout=10,
    )
    assert share_response.status_code in (302, 303)

    bob = _login("bob", "De586:Iq6}?!")

                                                           
    pre_details = bob.get(_url(f"/documents/{document_id}"), timeout=10)
    pre_download = bob.get(_url(f"/documents/{document_id}/download"), timeout=10)
    pre_shared = bob.get(_url(f"/shared/{document_id}/download"), timeout=10)

    assert pre_details.status_code == 200
    assert pre_download.status_code == 200
    assert pre_download.content == content
    assert pre_shared.status_code == 200

                                 
    csrf_token = _get_csrf_token(alice, _url(f"/documents/{document_id}"))
    revoke_response = alice.post(
        _url(f"/documents/{document_id}/revoke"),
        data={"shared_with": str(bob_id), "csrf_token": csrf_token},
        allow_redirects=False,
        timeout=10,
    )
    assert revoke_response.status_code in (302, 303)

                                                                       
    post_details = bob.get(_url(f"/documents/{document_id}"), timeout=10)
    post_download = bob.get(_url(f"/documents/{document_id}/download"), timeout=10)
    post_shared = bob.get(_url(f"/shared/{document_id}/download"), timeout=10)

    assert post_details.status_code == 404
    assert post_download.status_code == 404
    assert post_shared.status_code == 404


def test_authenticated_responses_disable_caching():
    """
    Scenario 7 hardening: authenticated content must not be cacheable,
    preventing stale content after permission revocation.
    """
    _wait_for_service()

    alice = _login("alice", "tth1mJj5?£58")
    response = alice.get(_url("/documents"), timeout=10)

    assert response.status_code == 200
    cache_control = response.headers.get("Cache-Control", "")
    pragma = response.headers.get("Pragma", "")
    expires = response.headers.get("Expires", "")

    assert "no-store" in cache_control
    assert "no-cache" in cache_control
    assert "must-revalidate" in cache_control
    assert pragma.lower() == "no-cache"
    assert expires == "0"
