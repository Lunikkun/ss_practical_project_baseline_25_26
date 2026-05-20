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

def test_idor_protection_download_endpoint():

    _wait_for_service()

    unique_title = f"idor-test-{uuid.uuid4().hex[:8]}"
    file_content = b"secret document only for alice"

    alice = _login("alice", "tth1mJj5?£58")
    _upload_document(alice, unique_title, "secret.txt", file_content)
    document_id = _find_document_id(alice, unique_title)

    bob = _login("bob", "De586:Iq6}?!")

    download_response = bob.get(_url(f"/documents/{document_id}/download"), timeout=10)
    assert download_response.status_code == 404, \
        "Bob should not be able to download Alice's document"

def test_idor_protection_details_endpoint():

    _wait_for_service()

    unique_title = f"idor-details-{uuid.uuid4().hex[:8]}"

    alice = _login("alice", "tth1mJj5?£58")
    _upload_document(alice, unique_title, "details.txt", b"private info")
    document_id = _find_document_id(alice, unique_title)

    bob = _login("bob", "De586:Iq6}?!")

    details_response = bob.get(_url(f"/documents/{document_id}"), timeout=10)
    assert details_response.status_code == 404, \
        "Bob should not be able to view Alice's document details"
    assert unique_title not in details_response.text, \
        "Document title should not be leaked in error response"

def test_idor_protection_share_endpoint():

    _wait_for_service()

    unique_title = f"idor-share-{uuid.uuid4().hex[:8]}"

    alice = _login("alice", "tth1mJj5?£58")
    _upload_document(alice, unique_title, "tosharefail.txt", b"mine")
    document_id = _find_document_id(alice, unique_title)

    bob = _login("bob", "De586:Iq6}?!")

    bob_csrf = _get_csrf_token(bob, _url("/login"))
    share_response = bob.post(
        _url(f"/documents/{document_id}/share"),
        data={"shared_with": "1", "csrf_token": bob_csrf},
        allow_redirects=False,
        timeout=10,
    )
    assert share_response.status_code == 403, \
        "Reviewer Bob should be blocked from share operations"

def test_idor_protection_shared_download_endpoint():

    _wait_for_service()

    unique_title = f"idor-shared-download-{uuid.uuid4().hex[:8]}"
    file_content = b"alice private file"

    alice = _login("alice", "tth1mJj5?£58")
    _upload_document(alice, unique_title, "private.txt", file_content)
    document_id = _find_document_id(alice, unique_title)

    bob = _login("bob", "De586:Iq6}?!")

    shared_download_response = bob.get(
        _url(f"/shared/{document_id}/download"),
        timeout=10,
    )
    assert shared_download_response.status_code == 404, \
        "Bob should not be able to access shared download for non-shared document"
