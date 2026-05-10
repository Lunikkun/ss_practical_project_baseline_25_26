import requests

from test_utils import _login, _url, _wait_for_service, _extract_user_id_from_admin_page


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
