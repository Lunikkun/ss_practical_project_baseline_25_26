import uuid
import pathlib

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


def test_download_document_detects_integrity_mismatch():
    _wait_for_service()

    upload_dir = pathlib.Path("web/uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)
    files_before = {entry.name for entry in upload_dir.iterdir() if entry.is_file()}

    unique_title = f"step1-download-integrity-{uuid.uuid4().hex[:8]}"
    file_content = b"step1 integrity test"

    alice = _login("alice", "tth1mJj5?£58")
    _upload_document(alice, unique_title, "integrity.txt", file_content)
    document_id = _find_document_id(alice, unique_title)

    files_after = {entry.name for entry in upload_dir.iterdir() if entry.is_file()}
    new_files = files_after - files_before
    assert len(new_files) >= 1, "Uploaded file not found on disk"

    newest_file_name = max(
        new_files,
        key=lambda name: (upload_dir / name).stat().st_mtime,
    )
    tampered_path = upload_dir / newest_file_name
    tampered_path.write_bytes(b"tampered-by-test")

    mismatch_download = alice.get(_url(f"/documents/{document_id}/download"), timeout=10)
    assert mismatch_download.status_code == 500
