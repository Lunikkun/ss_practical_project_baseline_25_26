import os
import re
import time

import pytest
import requests

from test_utils import _url, _wait_for_service


LOGIN_IP_RATE_WINDOW = 60


def _get_session_cookie_value(session: requests.Session) -> str:
                                                                               
    return session.cookies.get("__Host-session") or session.cookies.get("session")


def _login_and_get_response(username: str, password: str):
    session = requests.Session()
    login_page = session.get(_url("/login"), timeout=10)
    assert login_page.status_code == 200

    csrf_match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', login_page.text)
    assert csrf_match is not None, "CSRF token missing on login page"
    csrf_token = csrf_match.group(1)

    response = session.post(
        _url("/login"),
        data={"username": username, "password": password, "csrf_token": csrf_token},
        allow_redirects=False,
        timeout=10,
    )

    if response.status_code == 429:
        time.sleep(LOGIN_IP_RATE_WINDOW + 1)
        login_page = session.get(_url("/login"), timeout=10)
        assert login_page.status_code == 200
        csrf_match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', login_page.text)
        assert csrf_match is not None, "CSRF token missing on login page"
        csrf_token = csrf_match.group(1)
        response = session.post(
            _url("/login"),
            data={"username": username, "password": password, "csrf_token": csrf_token},
            allow_redirects=False,
            timeout=10,
        )
    return session, response


def test_session_cookie_flags_present_on_login():
    """
    Verify that the session cookie includes baseline anti-hijacking flags
    at browser level: HttpOnly and SameSite.
    """
    _wait_for_service()

    _, login_response = _login_and_get_response("alice", "tth1mJj5?£58")
    assert login_response.status_code in (302, 303)

    set_cookie = login_response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in set_cookie, "Session cookie must include HttpOnly"
    assert "SameSite=" in set_cookie, "Session cookie must include SameSite"


def test_session_replay_rejected_on_fingerprint_mismatch():
    """
    Simulate stolen-cookie replay from a client with a different User-Agent.
    With session fingerprinting enabled, replay must be invalidated.
    """
    _wait_for_service()

    victim, login_response = _login_and_get_response("alice", "tth1mJj5?£58")
    assert login_response.status_code in (302, 303)

    stolen_cookie = _get_session_cookie_value(victim)
    assert stolen_cookie, "Expected a valid session cookie after login"

    attacker = requests.Session()
    replay = attacker.get(
        _url("/documents"),
        headers={
            "Cookie": f"session={stolen_cookie}; __Host-session={stolen_cookie}",
            "User-Agent": "attacker-browser/1.0",
        },
        allow_redirects=False,
        timeout=10,
    )

    assert replay.status_code in (302, 303), (
        f"Expected replay to be rejected with redirect, got {replay.status_code}"
    )
    assert replay.headers.get("Location") == "/login", "Replay must be redirected to login"


def test_hsts_and_csp_headers_are_present():
    """
    Verify presence of supporting anti-hijacking/XSS headers:
    HSTS and CSP.
    """
    _wait_for_service()

    response = requests.get(_url("/health"), timeout=10)
    assert response.status_code == 200

    hsts = response.headers.get("Strict-Transport-Security", "")
    csp = response.headers.get("Content-Security-Policy", "")

    assert "max-age=" in hsts, "Missing Strict-Transport-Security max-age"
    assert "default-src 'self'" in csp, "Missing baseline Content-Security-Policy"


def test_client_script_avoids_innerhtml_sink():
    """
    XSS regression: client code must not use innerHTML with external input.
    """
    with open("web/static/script.js", "r", encoding="utf-8") as f:
        script = f.read()

    assert "innerHTML" not in script, "innerHTML sink found in script.js"
    assert "textContent" in script, "Expected safe textContent rendering in script.js"


def test_https_forced_uses_secure_host_prefixed_cookie():
    """
    If FORCE_HTTPS=1, session cookie must be Secure and use the __Host-
    prefix to reduce cookie confusion/injection risk.
    """
    if os.getenv("FORCE_HTTPS", "0") != "1":
        pytest.skip("FORCE_HTTPS is not enabled in this environment")

    _wait_for_service()

    _, login_response = _login_and_get_response("alice", "tth1mJj5?£58")
    assert login_response.status_code in (302, 303)

    set_cookie = login_response.headers.get("Set-Cookie", "")
    assert "Secure" in set_cookie, "Session cookie must include Secure when FORCE_HTTPS=1"
    assert "__Host-session=" in set_cookie, "Session cookie name should be __Host-session"
