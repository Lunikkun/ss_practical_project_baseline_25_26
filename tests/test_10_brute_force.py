import os
import re
import time
import uuid

import pytest
import requests

BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")

                                                                               
                                                                    
LOCKOUT_THRESHOLD = int(os.getenv("LOGIN_LOCKOUT_THRESHOLD", "5"))
LOGIN_IP_RATE_WINDOW = int(os.getenv("LOGIN_IP_RATE_WINDOW", "60"))

def _url(path: str) -> str:
    return f"{BASE_URL}/{path.lstrip('/')}"


def _get_csrf_token(session: requests.Session, url: str) -> str:
    """GET the login page and extract csrf_token from the hidden form input."""
    resp = session.get(url, timeout=10)
    assert resp.status_code == 200, f"GET {url} returned {resp.status_code}"
    match = re.search(r'<input[^>]+name="csrf_token"[^>]+value="([^"]+)"', resp.text)
    assert match is not None, "CSRF token non trovato nella pagina di login"
    return match.group(1)


def _post_login(session: requests.Session, username: str, password: str) -> requests.Response:
    """POST to /login using a valid CSRF token with redirects disabled."""
    csrf = _get_csrf_token(session, _url("/login"))
    return session.post(
        _url("/login"),
        data={"username": username, "password": password, "csrf_token": csrf},
        allow_redirects=False,
        timeout=10,
    )


def _new_probe_user(prefix: str = "pentest_lockout_probe") -> str:
    """Generate a unique fake username to avoid shared state across runs."""
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _lockout_account(session: requests.Session, username: str) -> requests.Response:
    """Perform failed attempts until lockout is reached and return the 429 response."""
    _ensure_login_not_rate_limited(session)
    for i in range(LOCKOUT_THRESHOLD):
        resp = _post_login(session, username, f"wrongpass_{i}")
        assert resp.status_code == 200, (
            f"Tentativo {i + 1}/{LOCKOUT_THRESHOLD}: atteso 200, ricevuto {resp.status_code}"
        )
    resp_locked = _post_login(session, username, "still_wrong")
    assert resp_locked.status_code == 429, (
        f"Atteso 429 dopo {LOCKOUT_THRESHOLD} tentativi falliti, ricevuto {resp_locked.status_code}"
    )
    return resp_locked


def _ensure_login_not_rate_limited(session: requests.Session):
    """If IP is already rate-limited from previous runs, wait for window reset."""
    probe_user = _new_probe_user("ip_warmup")
    probe_resp = _post_login(session, probe_user, "wrongpass")
    if probe_resp.status_code != 429:
        return

    time.sleep(LOGIN_IP_RATE_WINDOW + 1)
    retry_user = _new_probe_user("ip_warmup_retry")
    retry_resp = _post_login(session, retry_user, "wrongpass")
    assert retry_resp.status_code != 429, (
        "IP still in rate limiting"
    )


def _prepare_locked_probe_user() -> str:
    """Prepare a fake locked account while handling residual IP rate-limiting."""
    session = requests.Session()
    while True:
        fake_user = _new_probe_user()
        _ensure_login_not_rate_limited(session)

        ip_limited = False
        for i in range(LOCKOUT_THRESHOLD):
            resp = _post_login(session, fake_user, f"wrongpass_{i}")
            if resp.status_code == 429:
                ip_limited = True
                break

        if ip_limited:
            time.sleep(LOGIN_IP_RATE_WINDOW + 1)
            continue

        resp_locked = _post_login(session, fake_user, "still_wrong")
        if resp_locked.status_code == 429 and "Account temporarily locked" in resp_locked.text:
            return fake_user

                                                                                         
        time.sleep(LOGIN_IP_RATE_WINDOW + 1)


@pytest.fixture(scope="module")
def locked_probe_user() -> str:
    return _prepare_locked_probe_user()


                                                                             
                           
                                                                             

def test_brute_force_user_enumeration_same_message():
    """
    The response error message must be identical for an unknown user and for a
    real user with wrong password, preventing account enumeration by text diff.
    """
    _ensure_login_not_rate_limited(requests.Session())

    session_nonexistent = requests.Session()
    resp_nonexistent = _post_login(session_nonexistent, "nonexistent_xyz_9999", "wrongpass")

    session_wrong_pw = requests.Session()
    resp_wrong_pw = _post_login(session_wrong_pw, "alice", "definitelywrongpassword")

                                                                                               
    if resp_nonexistent.status_code == 429 or resp_wrong_pw.status_code == 429:
        time.sleep(LOGIN_IP_RATE_WINDOW + 1)
        session_nonexistent = requests.Session()
        resp_nonexistent = _post_login(session_nonexistent, "nonexistent_xyz_9999", "wrongpass")
        session_wrong_pw = requests.Session()
        resp_wrong_pw = _post_login(session_wrong_pw, "alice", "definitelywrongpassword")

                                                                                   
    assert resp_nonexistent.status_code == 200, (
        f"Atteso 200 per utente inesistente, ricevuto {resp_nonexistent.status_code}"
    )
    assert resp_wrong_pw.status_code == 200, (
        f"Atteso 200 per password errata, ricevuto {resp_wrong_pw.status_code}"
    )

                                                              
    assert "Invalid credentials." in resp_nonexistent.text, (
        "Messaggio 'Invalid credentials.' assente per utente inesistente"
    )
    assert "Invalid credentials." in resp_wrong_pw.text, (
        "Messaggio 'Invalid credentials.' assente per password errata"
    )


                                                                             
                          
                                                                             

def test_brute_force_account_lockout_triggers():
    """
    After LOGIN_LOCKOUT_THRESHOLD failed attempts on the same account,
    the system must return 429 instead of 200.
    """
    session = requests.Session()
    fake_user = _new_probe_user()
    _lockout_account(session, fake_user)


def test_brute_force_account_lockout_message(locked_probe_user):
    """
    When account lockout is active, the response should show lockout messaging
    rather than generic invalid credentials.
    """
    session = requests.Session()
    resp = _post_login(session, locked_probe_user, "any_password")

    assert resp.status_code == 429, (
        f"Atteso 429 per account bloccato, ricevuto {resp.status_code}"
    )
    assert "locked" in resp.text.lower() or "later" in resp.text.lower(), (
        "Messaggio di lockout assente nella risposta 429"
    )


def test_brute_force_valid_user_not_affected_by_other_lockout(locked_probe_user):
    """
    Lockout of a probe account must NOT impact legitimate accounts:
    alice must still be able to log in.
    """
                                                                                    
    assert locked_probe_user

    session = requests.Session()
    resp = _post_login(session, "alice", "tth1mJj5?£58")

                                                     
    assert resp.status_code in (302, 303), (
        f"Login alice fallito dopo lockout di altro account: {resp.status_code}"
    )


                                                                             
                           
                                                                             

def test_brute_force_ip_rate_limit_triggers():
    """
    After LOGIN_IP_RATE_LIMIT POST requests in the same minute from the same IP,
    the system must return 429.
    Uses a fake username sequence to avoid interfering with lockout tests.
    """
    ip_rate_limit = int(os.getenv("LOGIN_IP_RATE_LIMIT", "50"))
                                                       
    session = requests.Session()
    last_status = None
    for i in range(ip_rate_limit + 1):
        resp = _post_login(session, f"ip_test_probe_{i}", "wrongpass")
        last_status = resp.status_code
        if resp.status_code == 429:
            break

    assert last_status == 429, (
        f"Atteso 429 dopo {ip_rate_limit + 1} richieste dallo stesso IP, "
        f"ultimo status: {last_status}"
    )


                                                                             
                                                          
                                                                             

def test_brute_force_security_headers_on_429(locked_probe_user):
    """
    429 responses must include the same security headers configured
    by @after_request.
    """
    session = requests.Session()
    resp = _post_login(session, locked_probe_user, "any")

    assert resp.status_code == 429
    assert resp.headers.get("X-Frame-Options") == "DENY", "X-Frame-Options assente su 429"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff", (
        "X-Content-Type-Options assente su 429"
    )
