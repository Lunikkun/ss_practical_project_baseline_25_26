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


def test_shared_download_requires_active_share():
    _wait_for_service()

    unique_title = f"step3-shared-download-{uuid.uuid4().hex[:8]}"
    file_content = b"step3 shared download endpoint test"

    alice = _login("alice", "tth1mJj5?£58")
    _upload_document(alice, unique_title, "step3.txt", file_content)
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

    shared_download = bob.get(_url(f"/shared/{document_id}/download"), timeout=10)
    assert shared_download.status_code == 200
    assert shared_download.content == file_content

    csrf_token = _get_csrf_token(alice, _url(f"/documents/{document_id}"))
    revoke_response = alice.post(
        _url(f"/documents/{document_id}/revoke"),
        data={"shared_with": str(bob_id), "csrf_token": csrf_token},
        allow_redirects=False,
        timeout=10,
    )
    assert revoke_response.status_code in (302, 303)

    shared_download_after_revoke = bob.get(_url(f"/shared/{document_id}/download"), timeout=10)
    assert shared_download_after_revoke.status_code == 404
