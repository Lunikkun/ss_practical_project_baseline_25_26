import requests
from test_utils import _url, _wait_for_service, _get_csrf_token

def test_login_logout_flow():

    session = requests.Session()                                                              
    csrf_token = _get_csrf_token(session, _url("/login"))
    login_resp = session.post(
        _url("/login"),
        data={
            "username": "alice",
            "password": "tth1mJj5?£58",
            "csrf_token": csrf_token,
        },
        allow_redirects=False,
        timeout=10,
    )

    assert login_resp.status_code in (302, 303), (
        f"Login failed unexpectedly: {login_resp.status_code}"
    )
                                                           
    documents_resp = session.get(
        _url("/documents"),
        allow_redirects=False,
        timeout=10,
    )

    assert documents_resp.status_code == 200, (
        "Authenticated user cannot access /documents"
    )
                                                          
    logout_resp = session.get(
        _url("/logout"),
        allow_redirects=False,
        timeout=10,
    )

    assert logout_resp.status_code in (302, 303), (
        f"Logout failed unexpectedly: {logout_resp.status_code}"
    )

    after_logout = session.get(
        _url("/documents"),
        allow_redirects=False,
        timeout=10,
    )
    assert after_logout.status_code in (302, 303), (
        "Protected page still accessible after logout"
    )