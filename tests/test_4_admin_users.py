from test_utils import _login, _url, _wait_for_service


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
