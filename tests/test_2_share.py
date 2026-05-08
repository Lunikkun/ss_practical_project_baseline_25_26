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


def _find_user_id_from_share_form(session: requests.Session, document_id: int, username: str) -> int:
    response = session.get(_url(f"/documents/{document_id}"), timeout=10)
    assert response.status_code == 200

    pattern = rf"<option value=\"(\d+)\">{re.escape(username)} \(id: \d+\)</option>"
    match = re.search(pattern, response.text)
    assert match is not None, f"User {username} not found in share options"
    return int(match.group(1))


def test_share_document_requires_owner_or_admin_and_enables_access_for_target_user():
    _wait_for_service()

    unique_title = f"step2-share-{uuid.uuid4().hex[:8]}"
    file_content = b"step2 share endpoint test"

    alice = _login("alice", "tth1mJj5?\u00a358")
    _upload_document(alice, unique_title, "step2.txt", file_content)
    document_id = _find_document_id(alice, unique_title)

    bob_id = _find_user_id_from_share_form(alice, document_id, "bob")

    share_response = alice.post(
        _url(f"/documents/{document_id}/share"),
        data={"shared_with": str(bob_id)},
        allow_redirects=False,
        timeout=10,
    )
    assert share_response.status_code in (302, 303)

    bob = _login("bob", "De586:Iq6}?!")
    bob_documents = bob.get(_url("/documents"), timeout=10)
    assert bob_documents.status_code == 200
    assert unique_title not in bob_documents.text

    bob_shared = bob.get(_url("/shared"), timeout=10)
    assert bob_shared.status_code == 200
    assert unique_title in bob_shared.text

    bob_details = bob.get(_url(f"/documents/{document_id}"), timeout=10)
    assert bob_details.status_code == 200

    revoke_response = alice.post(
        _url(f"/documents/{document_id}/revoke"),
        data={"shared_with": str(bob_id)},
        allow_redirects=False,
        timeout=10,
    )
    assert revoke_response.status_code in (302, 303)

    bob_shared_after_revoke = bob.get(_url("/shared"), timeout=10)
    assert bob_shared_after_revoke.status_code == 200
    assert unique_title not in bob_shared_after_revoke.text

    bob_details_after_revoke = bob.get(_url(f"/documents/{document_id}"), timeout=10)
    assert bob_details_after_revoke.status_code == 403

    forbidden_share = bob.post(
        _url(f"/documents/{document_id}/share"),
        data={"shared_with": "1"},
        timeout=10,
    )
    assert forbidden_share.status_code == 403
