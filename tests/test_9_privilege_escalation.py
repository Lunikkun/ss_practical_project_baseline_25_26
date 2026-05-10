import requests

from test_utils import _login, _url, _wait_for_service, _get_csrf_token


def test_privilege_escalation_direct_endpoint_access():
    """
    Test escalation di privilegi diretto: tenta di accedere a /admin/users
    come alice (utente standard) per leggere la lista amministrativa.
    
    Vettore: Bypass del controllo is_admin_session()
    Risultato atteso: 403 Forbidden
    """
    _wait_for_service()

    alice = _login("alice", "tth1mJj5?£58")

    response = alice.get(_url("/admin/users"), timeout=10)
    assert response.status_code == 403, \
        f"Expected 403, got {response.status_code}: Alice should not access /admin/users"
    assert "Forbidden" in response.text or response.status_code == 403


def test_privilege_escalation_admin_action_as_user():
    """
    Test escalation: tenta di disabilitare un utente come alice (POST verso /admin/users/<id>/disable).
    Include un CSRF token valido per testare il controllo RBAC (non il CSRF).
    
    Vettore: Bypass del controllo RBAC su endpoint POST amministrativo
    Risultato atteso: 403 Forbidden
    """
    _wait_for_service()

    alice = _login("alice", "tth1mJj5?£58")
    bob_id = 3

    alice_csrf = _get_csrf_token(alice, _url("/documents"))
    response = alice.post(
        _url(f"/admin/users/{bob_id}/disable"),
        data={"csrf_token": alice_csrf},
        allow_redirects=False,
        timeout=10,
    )
    assert response.status_code == 403, \
        f"Expected 403, got {response.status_code}: Alice should not disable users"


def test_privilege_escalation_session_tampering_cookie_injection():
    """
    Test escalation tramite manomissione cookie di sessione:
    - Alice si autentica normalmente
    - Si prova a modificare il cookie Flask (es. aggiungere role=admin) per falsare la sessione
    - Si tenta accesso a /admin/users
    
    Vettore: Manomissione del cookie di sessione (se non firmato/criptato)
    Risultato atteso: 403 Forbidden (Flask firma i cookie con SECRET_KEY)
    """
    _wait_for_service()

    alice_session = requests.Session()

    csrf_token = _get_csrf_token(alice_session, _url("/login"))
    response = alice_session.post(
        _url("/login"),
        data={"username": "alice", "password": "tth1mJj5?£58", "csrf_token": csrf_token},
        allow_redirects=False,
        timeout=10,
    )
    assert response.status_code in (302, 303)

    original_cookies = alice_session.cookies.copy()
    
    tampered_session = requests.Session()
    tampered_session.cookies.update(original_cookies)
    
    response_before_tampering = tampered_session.get(_url("/admin/users"), timeout=10)
    assert response_before_tampering.status_code == 403

    if "session" in tampered_session.cookies:
        old_session_cookie = tampered_session.cookies.get("session")
        tampered_session.cookies.set("session", old_session_cookie + "TAMPEREDDATA")
        
        response_after_tampering = tampered_session.get(_url("/admin/users"), timeout=10)
        assert response_after_tampering.status_code in (302, 403), \
            "Tampered session should be rejected or redirect to login"


def test_privilege_escalation_disabled_user_session_persistence():
    """
    Test escalation via session persistence dopo disabilitamento:
    1. Alice si autentica e riceve una sessione valida.
    2. Admin disabilita alice via /admin/users/<alice_id>/disable.
    3. Alice prova a usare la vecchia sessione per accedere a /documents.
    
    Vettore: Sessione non invalidata al disabilitamento utente
    Risultato atteso: Redirect a login (302) perché is_disabled viene controllato ad ogni request
    """
    _wait_for_service()

    admin = _login("admin", "L|fP1D%327mB")
    alice = _login("alice", "tth1mJj5?£58")

    alice_id = 2

    alice_documents_before = alice.get(_url("/documents"), timeout=10)
    assert alice_documents_before.status_code == 200, "Alice should access /documents before disabling"

    admin_csrf = _get_csrf_token(admin, _url("/admin/users"))
    disable_response = admin.post(
        _url(f"/admin/users/{alice_id}/disable"),
        data={"csrf_token": admin_csrf},
        allow_redirects=False,
        timeout=10,
    )
    assert disable_response.status_code in (302, 303), "Admin should successfully disable alice"

    alice_documents_after = alice.get(_url("/documents"), allow_redirects=False, timeout=10)
    assert alice_documents_after.status_code in (302, 303), \
        "Disabled user should be redirected to login (is_disabled checked per-request)"

    # Clean up: re-enable alice for subsequent tests
    admin_csrf = _get_csrf_token(admin, _url("/admin/users"))
    admin.post(
        _url(f"/admin/users/{alice_id}/enable"),
        data={"csrf_token": admin_csrf},
        allow_redirects=False,
        timeout=10,
    )


def test_privilege_escalation_force_admin_action_unauthenticated():
    """
    Test escalation: tenta di accedere a endpoint admin senza autenticazione.
    
    Vettore: Bypass del decoratore @login_required
    Risultato atteso: Redirect a /login (302/303)
    """
    _wait_for_service()

    unauthenticated = requests.Session()

    response = unauthenticated.get(_url("/admin/users"), allow_redirects=False, timeout=10)
    assert response.status_code in (302, 303), \
        "Unauthenticated user should be redirected to login"


def test_privilege_escalation_cross_site_request_forgery_admin_action():
    """
    Test escalation via CSRF: tenta una POST verso /admin/users/<id>/disable
    senza CSRF token per verificare se il backend valida il token.
    
    Vettore: Mancanza di validazione CSRF token (attacco cross-site)
    Risultato atteso: 400 Bad Request (CSRF token mancante/invalido)
    """
    _wait_for_service()

    alice = _login("alice", "tth1mJj5?£58")
    bob_id = 3

    # Simulate CSRF attack: POST without token (as a cross-site attacker would)
    post_response = alice.post(
        _url(f"/admin/users/{bob_id}/disable"),
        data={},
        allow_redirects=False,
        timeout=10,
    )

    assert post_response.status_code in (400, 403), \
        f"Expected 400 (CSRF rejected) or 403 (RBAC), got {post_response.status_code}"
