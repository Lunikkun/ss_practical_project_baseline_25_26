import os
import re
import time

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


def _extract_user_id_from_admin_page(page_html: str, username: str) -> int:
    pattern = rf"<td>(\d+)</td>\s*<td>{re.escape(username)}</td>"
    match = re.search(pattern, page_html)
    assert match is not None, f"User {username} not found in admin users table"
    return int(match.group(1))


def test_admin_enable_disable_endpoints_enforce_rbac_and_toggle_user_status():
    _wait_for_service()

    admin = _login("admin", "L|fP1D%327mB")
    admin_users_page = admin.get(_url("/admin/users"), timeout=10)
    assert admin_users_page.status_code == 200

    bob_id = _extract_user_id_from_admin_page(admin_users_page.text, "bob")

    disable_resp = admin.post(
        _url(f"/admin/users/{bob_id}/disable"),
        allow_redirects=False,
        timeout=10,
    )
    assert disable_resp.status_code in (302, 303)

    bob = requests.Session()
    bob_login_while_disabled = bob.post(
        _url("/login"),
        data={"username": "bob", "password": "De586:Iq6}?!"},
        allow_redirects=False,
        timeout=10,
    )
    assert bob_login_while_disabled.status_code == 200

    enable_resp = admin.post(
        _url(f"/admin/users/{bob_id}/enable"),
        allow_redirects=False,
        timeout=10,
    )
    assert enable_resp.status_code in (302, 303)

    bob_after_enable = _login("bob", "De586:Iq6}?!")
    documents_page = bob_after_enable.get(_url("/documents"), timeout=10)
    assert documents_page.status_code == 200

    alice = _login("alice", "tth1mJj5?\u00a358")
    forbidden_disable = alice.post(_url(f"/admin/users/{bob_id}/disable"), timeout=10)
    assert forbidden_disable.status_code == 403
