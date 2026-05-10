import uuid

from test_utils import _login, _url, _wait_for_service, _upload_document, _find_document_id


def test_download_document_requires_authorized_access():
    _wait_for_service()

    unique_title = f"step1-download-{uuid.uuid4().hex[:8]}"
    file_content = b"step1 download endpoint test"

    alice = _login("alice", "tth1mJj5?£58")
    _upload_document(alice, unique_title, "step1.txt", file_content)
    document_id = _find_document_id(alice, unique_title)

    own_download = alice.get(_url(f"/documents/{document_id}/download"), timeout=10)
    assert own_download.status_code == 200
    assert own_download.content == file_content

    bob = _login("bob", "De586:Iq6}?!")
    forbidden_download = bob.get(_url(f"/documents/{document_id}/download"), timeout=10)
    assert forbidden_download.status_code == 404
