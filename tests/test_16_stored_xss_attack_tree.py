import io
import os
import time
import uuid
from test_utils import _find_document_id, _get_csrf_token, _login, _url, _wait_for_service

MALICIOUS_TITLE = "<script>alert('xss')</script>"
MALICIOUS_FILENAME = "<script>alert(1)</script>.txt"
UPLOAD_RATE_WINDOW = int(os.getenv("UPLOAD_RATE_WINDOW", "60"))

def test_stored_xss_attack_tree_rejects_malicious_title_payload():

    _wait_for_service()

    alice = _login("alice", "tth1mJj5?£58")
    csrf_token = _get_csrf_token(alice, _url("/documents"))

    upload_response = alice.post(
        _url("/documents/upload"),
        data={"title": MALICIOUS_TITLE, "csrf_token": csrf_token},
        files={"document": ("safe.txt", io.BytesIO(b"safe"), "text/plain")},
        allow_redirects=False,
        timeout=10,
    )
    if upload_response.status_code == 429:
        time.sleep(UPLOAD_RATE_WINDOW + 1)
        csrf_token = _get_csrf_token(alice, _url("/documents"))
        upload_response = alice.post(
            _url("/documents/upload"),
            data={"title": MALICIOUS_TITLE, "csrf_token": csrf_token},
            files={"document": ("safe.txt", io.BytesIO(b"safe"), "text/plain")},
            allow_redirects=False,
            timeout=10,
        )

    assert upload_response.status_code in (302, 303)

    documents_page = alice.get(_url("/documents"), timeout=10)
    assert documents_page.status_code == 200
    assert "Invalid document title." in documents_page.text
    assert MALICIOUS_TITLE not in documents_page.text

def test_stored_xss_attack_tree_sanitizes_filename_and_no_raw_script_rendered():

    _wait_for_service()

    alice = _login("alice", "tth1mJj5?£58")
    unique_title = f"scenario10-safe-{uuid.uuid4().hex[:8]}"
    csrf_token = _get_csrf_token(alice, _url("/documents"))

    upload_response = alice.post(
        _url("/documents/upload"),
        data={"title": unique_title, "csrf_token": csrf_token},
        files={"document": (MALICIOUS_FILENAME, io.BytesIO(b"content"), "text/plain")},
        allow_redirects=False,
        timeout=10,
    )
    if upload_response.status_code == 429:
        time.sleep(UPLOAD_RATE_WINDOW + 1)
        csrf_token = _get_csrf_token(alice, _url("/documents"))
        upload_response = alice.post(
            _url("/documents/upload"),
            data={"title": unique_title, "csrf_token": csrf_token},
            files={"document": (MALICIOUS_FILENAME, io.BytesIO(b"content"), "text/plain")},
            allow_redirects=False,
            timeout=10,
        )
    assert upload_response.status_code in (302, 303)

    document_id = _find_document_id(alice, unique_title)

    documents_page = alice.get(_url("/documents"), timeout=10)
    details_page = alice.get(_url(f"/documents/{document_id}"), timeout=10)

    assert documents_page.status_code == 200
    assert details_page.status_code == 200
    assert MALICIOUS_FILENAME not in documents_page.text
    assert MALICIOUS_FILENAME not in details_page.text

def test_stored_xss_attack_tree_static_regression_no_unsafe_template_sinks():

    template_files = [
        "web/templates/base.html",
        "web/templates/documents.html",
        "web/templates/shared.html",
        "web/templates/document_details.html",
    ]

    for file_path in template_files:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "|safe" not in content
