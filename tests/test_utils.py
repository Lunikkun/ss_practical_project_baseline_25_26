"""
Shared utilities for test files.

Centralizes common functions used across all test modules to reduce duplication
and improve maintainability.
"""

import io
import os
import re
import time

import requests


BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")


def _url(path: str) -> str:
    """Construct a full URL from a path, using BASE_URL."""
    return f"{BASE_URL}/{path.lstrip('/')}"


def _wait_for_service(timeout: int = 30):
    """Poll the /health endpoint until the service is available or timeout."""
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
    """Login with username/password and return authenticated session."""
    session = requests.Session()
    response = session.post(
        _url("/login"),
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=10,
    )
    assert response.status_code in (302, 303), \
        f"Login failed for {username}: got {response.status_code}"
    return session


def _upload_document(session: requests.Session, title: str, filename: str, content: bytes):
    """Upload a document with given title and filename."""
    response = session.post(
        _url("/documents/upload"),
        data={"title": title},
        files={"document": (filename, io.BytesIO(content), "text/plain")},
        allow_redirects=False,
        timeout=10,
    )
    assert response.status_code in (302, 303), \
        f"Upload failed: got {response.status_code}"


def _find_document_id(session: requests.Session, title: str) -> int:
    """Find document ID by title in /documents page."""
    response = session.get(_url("/documents"), timeout=10)
    assert response.status_code == 200

    pattern = rf"<td>(\d+)</td>\s*<td>{re.escape(title)}</td>"
    match = re.search(pattern, response.text)
    assert match is not None, "Uploaded document not found in listing"
    return int(match.group(1))


def _find_user_id_from_share_form(session: requests.Session, document_id: int, username: str) -> int:
    """Extract user ID from share form options dropdown."""
    response = session.get(_url(f"/documents/{document_id}"), timeout=10)
    assert response.status_code == 200

    pattern = rf"<option value=\"(\d+)\">{re.escape(username)} \(id: \d+\)</option>"
    match = re.search(pattern, response.text)
    assert match is not None, f"User {username} not found in share options"
    return int(match.group(1))


def _extract_user_id_from_admin_page(page_html: str, username: str) -> int:
    """Extract user ID from admin users listing page."""
    pattern = rf"<tr[^>]*>\s*<td>(\d+)</td>\s*<td>{re.escape(username)}</td>"
    match = re.search(pattern, page_html)
    assert match is not None, f"User {username} not found in admin page"
    return int(match.group(1))
