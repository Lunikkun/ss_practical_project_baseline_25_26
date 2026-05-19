import uuid

from test_utils import (
    _login,
    _url,
    _wait_for_service,
    _upload_document,
    _find_document_id,
    _find_user_id_from_share_form,
    _get_csrf_token,
)


def test_share_document_requires_owner_or_admin_and_enables_access_for_target_user():
    _wait_for_service()

    unique_title = f"step2-share-{uuid.uuid4().hex[:8]}"
    file_content = b"step2 share endpoint test"

    alice = _login("alice", "tth1mJj5?£58")
    _upload_document(alice, unique_title, "step2.txt", file_content)
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
    bob_documents = bob.get(_url("/documents"), allow_redirects=False, timeout=10)
    assert bob_documents.status_code in (302, 303)
    assert bob_documents.headers.get("Location", "").endswith("/shared")

    bob_shared = bob.get(_url("/shared"), timeout=10)
    assert bob_shared.status_code == 200
    assert unique_title in bob_shared.text

    bob_details = bob.get(_url(f"/documents/{document_id}"), timeout=10)
    assert bob_details.status_code == 200

    csrf_token = _get_csrf_token(alice, _url(f"/documents/{document_id}"))
    revoke_response = alice.post(
        _url(f"/documents/{document_id}/revoke"),
        data={"shared_with": str(bob_id), "csrf_token": csrf_token},
        allow_redirects=False,
        timeout=10,
    )
    assert revoke_response.status_code in (302, 303)

    bob_shared_after_revoke = bob.get(_url("/shared"), timeout=10)
    assert bob_shared_after_revoke.status_code == 200
    assert unique_title not in bob_shared_after_revoke.text

    bob_details_after_revoke = bob.get(_url(f"/documents/{document_id}"), timeout=10)
    assert bob_details_after_revoke.status_code == 404

    bob_csrf_token = _get_csrf_token(bob, _url("/login"))
    forbidden_share = bob.post(
        _url(f"/documents/{document_id}/share"),
        data={"shared_with": "1", "csrf_token": bob_csrf_token},
        timeout=10,
    )
    assert forbidden_share.status_code == 403
