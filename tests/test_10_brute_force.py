"""
Scenario 4 – Brute Force & Credential Stuffing (Account Takeover)

Verifica le protezioni contro:
1. User Enumeration: risposte identiche per utente inesistente vs password errata.
2. Account Lockout: dopo LOGIN_LOCKOUT_THRESHOLD tentativi falliti l'account
   viene bloccato temporaneamente (HTTP 429).
3. IP Rate Limiting: dopo LOGIN_IP_RATE_LIMIT POST nello stesso minuto
   l'IP riceve HTTP 429.
4. Header di sicurezza presenti anche sulle risposte 429.
"""

import os
import re
import time
import uuid

import pytest
import requests

BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")

# Soglia di lockout per account (deve corrispondere a LOGIN_LOCKOUT_THRESHOLD).
# Di default 5; può essere abbassata via env per velocizzare i test.
LOCKOUT_THRESHOLD = int(os.getenv("LOGIN_LOCKOUT_THRESHOLD", "5"))
LOGIN_IP_RATE_WINDOW = int(os.getenv("LOGIN_IP_RATE_WINDOW", "60"))

def _url(path: str) -> str:
    return f"{BASE_URL}/{path.lstrip('/')}"


def _get_csrf_token(session: requests.Session, url: str) -> str:
    """GET la pagina di login ed estrae il csrf_token dal form hidden."""
    resp = session.get(url, timeout=10)
    assert resp.status_code == 200, f"GET {url} returned {resp.status_code}"
    match = re.search(r'<input[^>]+name="csrf_token"[^>]+value="([^"]+)"', resp.text)
    assert match is not None, "CSRF token non trovato nella pagina di login"
    return match.group(1)


def _post_login(session: requests.Session, username: str, password: str) -> requests.Response:
    """POST a /login con CSRF token valido; segue redirect=False."""
    csrf = _get_csrf_token(session, _url("/login"))
    return session.post(
        _url("/login"),
        data={"username": username, "password": password, "csrf_token": csrf},
        allow_redirects=False,
        timeout=10,
    )


def _new_probe_user(prefix: str = "pentest_lockout_probe") -> str:
    """Genera uno username fittizio unico per evitare stato condiviso tra run."""
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _lockout_account(session: requests.Session, username: str) -> requests.Response:
    """Esegue tentativi falliti finché l'account entra in lockout e ritorna la risposta 429."""
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
    """Se l'IP è già in rate-limit da run precedenti, aspetta il reset finestra."""
    probe_user = _new_probe_user("ip_warmup")
    probe_resp = _post_login(session, probe_user, "wrongpass")
    if probe_resp.status_code != 429:
        return

    time.sleep(LOGIN_IP_RATE_WINDOW + 1)
    retry_user = _new_probe_user("ip_warmup_retry")
    retry_resp = _post_login(session, retry_user, "wrongpass")
    assert retry_resp.status_code != 429, (
        "IP ancora in rate-limit dopo attesa finestra; stato ambiente non pulito"
    )


def _prepare_locked_probe_user() -> str:
    """Prepara un account fittizio in lockout, gestendo eventuale rate-limit IP residuo."""
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

        # Se 429 è dovuto a IP rate limit (o stato ambiguo), riprova dopo reset finestra.
        time.sleep(LOGIN_IP_RATE_WINDOW + 1)


@pytest.fixture(scope="module")
def locked_probe_user() -> str:
    return _prepare_locked_probe_user()


# ---------------------------------------------------------------------------
# Test 1 – User Enumeration
# ---------------------------------------------------------------------------

def test_brute_force_user_enumeration_same_message():
    """
    La risposta (messaggio di errore) deve essere identica sia per un
    utente inesistente sia per un utente reale con password errata.
    Questo previene l'enumerazione degli account tramite differenze testuali.
    """
    _ensure_login_not_rate_limited(requests.Session())

    session_nonexistent = requests.Session()
    resp_nonexistent = _post_login(session_nonexistent, "nonexistent_xyz_9999", "wrongpass")

    session_wrong_pw = requests.Session()
    resp_wrong_pw = _post_login(session_wrong_pw, "alice", "definitelywrongpassword")

    # Se la suite precedente ha quasi saturato il rate-limit IP, resetta la finestra e riprova.
    if resp_nonexistent.status_code == 429 or resp_wrong_pw.status_code == 429:
        time.sleep(LOGIN_IP_RATE_WINDOW + 1)
        session_nonexistent = requests.Session()
        resp_nonexistent = _post_login(session_nonexistent, "nonexistent_xyz_9999", "wrongpass")
        session_wrong_pw = requests.Session()
        resp_wrong_pw = _post_login(session_wrong_pw, "alice", "definitelywrongpassword")

    # Entrambe devono tornare 200 (pagina login con errore flash) e NON un redirect
    assert resp_nonexistent.status_code == 200, (
        f"Atteso 200 per utente inesistente, ricevuto {resp_nonexistent.status_code}"
    )
    assert resp_wrong_pw.status_code == 200, (
        f"Atteso 200 per password errata, ricevuto {resp_wrong_pw.status_code}"
    )

    # Il messaggio di errore deve essere identico nei due casi
    assert "Invalid credentials." in resp_nonexistent.text, (
        "Messaggio 'Invalid credentials.' assente per utente inesistente"
    )
    assert "Invalid credentials." in resp_wrong_pw.text, (
        "Messaggio 'Invalid credentials.' assente per password errata"
    )


# ---------------------------------------------------------------------------
# Test 2 – Account Lockout
# ---------------------------------------------------------------------------

def test_brute_force_account_lockout_triggers():
    """
    Dopo LOGIN_LOCKOUT_THRESHOLD tentativi falliti sullo stesso account
    (anche inesistente) il sistema deve rispondere 429 e non più 200.
    """
    session = requests.Session()
    fake_user = _new_probe_user()
    _lockout_account(session, fake_user)


def test_brute_force_account_lockout_message(locked_probe_user):
    """
    Quando l'account è bloccato, la pagina deve mostrare il messaggio
    di lockout (non 'Invalid credentials.').
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
    Il lockout di un account (pentest_lockout_probe) NON deve influenzare
    gli account legittimi: alice deve poter fare login normalmente.
    """
    # Accesso al fixture per garantire che almeno un account sia davvero in lockout.
    assert locked_probe_user

    session = requests.Session()
    resp = _post_login(session, "alice", "tth1mJj5?£58")

    # Login di alice deve riuscire → redirect 302/303
    assert resp.status_code in (302, 303), (
        f"Login alice fallito dopo lockout di altro account: {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Test 3 – IP Rate Limiting
# ---------------------------------------------------------------------------

def test_brute_force_ip_rate_limit_triggers():
    """
    Dopo LOGIN_IP_RATE_LIMIT POST nello stesso minuto dallo stesso IP
    il sistema deve rispondere 429.
    Usa un secondo username fittizio per non interferire con i lockout precedenti.
    """
    ip_rate_limit = int(os.getenv("LOGIN_IP_RATE_LIMIT", "50"))
    # Invia ip_rate_limit + 1 richieste dallo stesso IP
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


# ---------------------------------------------------------------------------
# Test 4 – Security headers presenti anche su risposte 429
# ---------------------------------------------------------------------------

def test_brute_force_security_headers_on_429(locked_probe_user):
    """
    Le risposte 429 devono includere gli stessi security headers
    configurati via @after_request.
    """
    session = requests.Session()
    resp = _post_login(session, locked_probe_user, "any")

    assert resp.status_code == 429
    assert resp.headers.get("X-Frame-Options") == "DENY", "X-Frame-Options assente su 429"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff", (
        "X-Content-Type-Options assente su 429"
    )
