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

    resp = session.get(url, timeout=10)
    assert resp.status_code == 200, f"GET {url} returned {resp.status_code}"
    match = re.search(r'<input[^>]+name="csrf_token"[^>]+value="([^"]+)"', resp.text)
    assert match is not None, "CSRF token not found on the login page"
    return match.group(1)

def _post_login(session: requests.Session, username: str, password: str) -> requests.Response:

    csrf = _get_csrf_token(session, _url("/login"))
    return session.post(
        _url("/login"),
        data={"username": username, "password": password, "csrf_token": csrf},
        allow_redirects=False,
        timeout=10,
    )

def _new_probe_user(prefix: str = "pentest_lockout_probe") -> str:

    return f"{prefix}_{uuid.uuid4().hex[:10]}"

def _lockout_account(session: requests.Session, username: str) -> requests.Response:

    _ensure_login_not_rate_limited(session)
    for i in range(LOCKOUT_THRESHOLD):
        resp = _post_login(session, username, f"wrongpass_{i}")
        assert resp.status_code == 200, (
            f"Attempt {i + 1}/{LOCKOUT_THRESHOLD}: expected 200, got {resp.status_code}"
        )
    resp_locked = _post_login(session, username, "still_wrong")
    assert resp_locked.status_code == 429, (
        f"Expected 429 after {LOCKOUT_THRESHOLD} failed attempts, got {resp_locked.status_code}"
    )
    return resp_locked

def _ensure_login_not_rate_limited(session: requests.Session):
  
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
        f"Expected 200, reviced {resp_nonexistent.status_code}"
    )
    assert resp_wrong_pw.status_code == 200, (
        f"Expected 200, recived {resp_wrong_pw.status_code}"
    )

                                                              
    assert "Invalid credentials." in resp_nonexistent.text, (
        "Message 'Invalid credentials.' absent"
    )
    assert "Invalid credentials." in resp_wrong_pw.text, (
        "Message 'Invalid credentials.' absent"
    )
                                                                  
def test_brute_force_account_lockout_triggers():

    session = requests.Session()
    fake_user = _new_probe_user()
    _lockout_account(session, fake_user)


def test_brute_force_account_lockout_message(locked_probe_user):

    session = requests.Session()
    resp = _post_login(session, locked_probe_user, "any_password")

    assert resp.status_code == 429, (
        f"Expected 429 for blocked account, recived {resp.status_code}"
    )
    assert "locked" in resp.text.lower() or "later" in resp.text.lower(), (
        "Absent lockout message"
    )

def test_brute_force_valid_user_not_affected_by_other_lockout(locked_probe_user):
                                                                           
    assert locked_probe_user

    session = requests.Session()
    resp = _post_login(session, "alice", "tth1mJj5?£58")
                                                
    assert resp.status_code in (302, 303), (
        f"Alice login failed after another account lockout: {resp.status_code}"
    )

def test_brute_force_ip_rate_limit_triggers():
 
    ip_rate_limit = int(os.getenv("LOGIN_IP_RATE_LIMIT", "50"))
                                                       
    session = requests.Session()
    last_status = None
    for i in range(ip_rate_limit + 1):
        resp = _post_login(session, f"ip_test_probe_{i}", "wrongpass")
        last_status = resp.status_code
        if resp.status_code == 429:
            break

    assert last_status == 429, (
        f"Expected 429 after {ip_rate_limit + 1} requests from same IP, "
        f"last status: {last_status}"
    )

def test_brute_force_security_headers_on_429(locked_probe_user):

    session = requests.Session()
    resp = _post_login(session, locked_probe_user, "any")

    assert resp.status_code == 429
    assert resp.headers.get("X-Frame-Options") == "DENY", "Missing X-Frame-Options on 429"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff", (
        "Missing X-Content-Type-Options on 429"
    )
