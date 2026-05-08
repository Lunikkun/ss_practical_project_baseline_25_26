import io
import os
import re
import time
import uuid

import requests


BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")


def _url(path: str) -> str:
    return f"{BASE_URL}/{path.lstrip('/')}"


def _wait_for_service(timeout: int = 30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = requests.get(_url("/health"), timeout=2)
            if response.ok:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise RuntimeError("Service not available")


def _login(username: str, password: str) -> requests.Session:
    session = requests.Session()
    response = session.post(
        _url("/login"),
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=10,
    )
    assert response.status_code in (302, 303)
    return session


def _upload_document(session: requests.Session, title: str, filename: str, content: bytes):
    response = session.post(
        _url("/documents/upload"),
        data={"title": title},
        files={"document": (filename, io.BytesIO(content), "text/plain")},
        allow_redirects=False,
        timeout=10,
    )
    assert response.status_code in (302, 303)


def _find_document_id(session: requests.Session, title: str) -> int:
    response = session.get(_url("/documents"), timeout=10)
    assert response.status_code == 200

    pattern = rf"<td>(\d+)</td>\s*<td>{re.escape(title)}</td>"
    match = re.search(pattern, response.text)
    assert match is not None, "Uploaded document not found in listing"
    return int(match.group(1))


def test_download_document_requires_authorized_access():
    _wait_for_service()

    unique_title = f"step1-download-{uuid.uuid4().hex[:8]}"
    file_content = b"step1 download endpoint test"

    alice = _login("alice", "tth1mJj5?\u00a358")
    _upload_document(alice, unique_title, "step1.txt", file_content)
    document_id = _find_document_id(alice, unique_title)

    own_download = alice.get(_url(f"/documents/{document_id}/download"), timeout=10)
    assert own_download.status_code == 200
    assert own_download.content == file_content

    bob = _login("bob", "De586:Iq6}?!")
    forbidden_download = bob.get(_url(f"/documents/{document_id}/download"), timeout=10)
    assert forbidden_download.status_code == 403
