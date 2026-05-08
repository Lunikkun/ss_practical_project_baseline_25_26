import os
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


def test_admin_users_requires_admin_role():
    _wait_for_service()

    admin = _login("admin", "L|fP1D%327mB")
    admin_users = admin.get(_url("/admin/users"), timeout=10)
    assert admin_users.status_code == 200
    assert "Registered users" in admin_users.text
    assert "alice" in admin_users.text
    assert "bob" in admin_users.text

    alice = _login("alice", "tth1mJj5?\u00a358")
    forbidden = alice.get(_url("/admin/users"), timeout=10)
    assert forbidden.status_code == 403
