import io
import os
import re
import time
import uuid

from test_utils import _login, _url, _wait_for_service, _get_csrf_token


UPLOAD_RATE_WINDOW = int(os.getenv("UPLOAD_RATE_WINDOW", "60"))


def test_upload_rejects_executable_script_extensions():
    _wait_for_service()

    alice = _login("alice", "tth1mJj5?£58")
    unique_title = f"blocked-upload-{uuid.uuid4().hex[:8]}"

    csrf_token = _get_csrf_token(alice, _url("/documents"))
    upload_response = alice.post(
        _url("/documents/upload"),
        data={"title": unique_title, "csrf_token": csrf_token},
        files={"document": ("payload.py", io.BytesIO(b"print('boom')"), "text/x-python")},
        allow_redirects=False,
        timeout=10,
    )
    if upload_response.status_code == 429:
        time.sleep(UPLOAD_RATE_WINDOW + 1)
        csrf_token = _get_csrf_token(alice, _url("/documents"))
        upload_response = alice.post(
            _url("/documents/upload"),
            data={"title": unique_title, "csrf_token": csrf_token},
            files={"document": ("payload.py", io.BytesIO(b"print('boom')"), "text/x-python")},
            allow_redirects=False,
            timeout=10,
        )
    assert upload_response.status_code in (302, 303)

    documents_response = alice.get(_url("/documents"), timeout=10)
    assert documents_response.status_code == 200
    assert unique_title not in documents_response.text
    assert "File type not allowed." in documents_response.text


def test_upload_accepts_safe_text_documents():
    _wait_for_service()

    alice = _login("alice", "tth1mJj5?£58")
    unique_title = f"safe-upload-{uuid.uuid4().hex[:8]}"

    csrf_token = _get_csrf_token(alice, _url("/documents"))
    upload_response = alice.post(
        _url("/documents/upload"),
        data={"title": unique_title, "csrf_token": csrf_token},
        files={"document": ("note.txt", io.BytesIO(b"safe content"), "text/plain")},
        allow_redirects=False,
        timeout=10,
    )
    if upload_response.status_code == 429:
        time.sleep(UPLOAD_RATE_WINDOW + 1)
        csrf_token = _get_csrf_token(alice, _url("/documents"))
        upload_response = alice.post(
            _url("/documents/upload"),
            data={"title": unique_title, "csrf_token": csrf_token},
            files={"document": ("note.txt", io.BytesIO(b"safe content"), "text/plain")},
            allow_redirects=False,
            timeout=10,
        )
    assert upload_response.status_code in (302, 303)

    documents_response = alice.get(_url("/documents"), timeout=10)
    assert documents_response.status_code == 200

    pattern = rf"<td>(\d+)</td>\s*<td>{re.escape(unique_title)}</td>"
    assert re.search(pattern, documents_response.text) is not None