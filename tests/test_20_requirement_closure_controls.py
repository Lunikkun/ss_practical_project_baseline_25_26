import pathlib
from test_utils import _extract_user_id_from_admin_page, _get_csrf_token, _login, _url, _wait_for_service

ROOT = pathlib.Path(__file__).resolve().parent.parent

def test_requirement_closure_reviewer_is_read_only_for_uploads():
    _wait_for_service()

    reviewer = _login("bob", "De586:Iq6}?!")

    response = reviewer.post(
        _url("/documents/upload"),
        data={"title": "reviewer-upload-attempt"},
        files={"document": ("blocked.txt", b"blocked", "text/plain")},
        timeout=10,
    )
    assert response.status_code in (400, 403)

def test_requirement_closure_reviewer_has_no_own_documents_page():
    _wait_for_service()

    reviewer = _login("bob", "De586:Iq6}?!")
    response = reviewer.get(_url("/documents"), allow_redirects=False, timeout=10)

    assert response.status_code in (302, 303)
    assert response.headers.get("Location", "").endswith("/shared")

def test_requirement_closure_admin_actions_require_justification():
    _wait_for_service()

    admin = _login("admin", "L|fP1D%327mB")
    users_page = admin.get(_url("/admin/users"), timeout=10)
    assert users_page.status_code == 200

    bob_id = _extract_user_id_from_admin_page(users_page.text, "bob")

    csrf_token = _get_csrf_token(admin, _url("/admin/users"))
    missing_justification = admin.post(
        _url(f"/admin/users/{bob_id}/disable"),
        data={"csrf_token": csrf_token},
        allow_redirects=False,
        timeout=10,
    )
    assert missing_justification.status_code == 400

    csrf_token = _get_csrf_token(admin, _url("/admin/users"))
    disable_ok = admin.post(
        _url(f"/admin/users/{bob_id}/disable"),
        data={"csrf_token": csrf_token, "justification": "incident response verification"},
        allow_redirects=False,
        timeout=10,
    )
    assert disable_ok.status_code in (302, 303)

    csrf_token = _get_csrf_token(admin, _url("/admin/users"))
    enable_ok = admin.post(
        _url(f"/admin/users/{bob_id}/enable"),
        data={"csrf_token": csrf_token, "justification": "restore operational access"},
        allow_redirects=False,
        timeout=10,
    )
    assert enable_ok.status_code in (302, 303)

def test_requirement_closure_static_markers_present():
    app_code = (ROOT / "web" / "app" / "app.py").read_text(encoding="utf-8")
    common_code = (ROOT / "web" / "app" / "routes" / "common.py").read_text(encoding="utf-8")
    documents_code = (ROOT / "web" / "app" / "routes" / "documents.py").read_text(encoding="utf-8")
    config_code = (ROOT / "web" / "app" / "config.py").read_text(encoding="utf-8")
    schema_sql = (ROOT / "db" / "init.sql").read_text(encoding="utf-8")
    ci_workflow = (ROOT / ".github" / "workflows" / "1-integration.yml").read_text(encoding="utf-8")
    pep_code = (ROOT / "web" / "app" / "security" / "pep.py").read_text(encoding="utf-8")
    input_controls_code = (ROOT / "web" / "app" / "security" / "input_controls.py").read_text(encoding="utf-8")
    storage_code = (ROOT / "web" / "app" / "services" / "storage_service.py").read_text(encoding="utf-8")

    assert "@app.errorhandler(Exception)" in app_code
    assert "return flask.render_template(\"error_generic.html\"), 500" in app_code
    assert "APP_SECURITY_PROFILE" in app_code
    assert "PolicyEnforcementPoint" in common_code
    assert "os.chmod(upload_folder, 0o700)" in documents_code
    assert "os.chmod(destination, 0o600)" in documents_code
    assert "upload_rate_limit" in config_code
    assert "user_max_files" in config_code
    assert "global_storage_quota_bytes" in config_code
    assert "role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user', 'reviewer'))" in schema_sql
    assert "CREATE TABLE audit_logs" in schema_sql
    assert "storage_key TEXT UNIQUE NOT NULL" in schema_sql
    assert "class PolicyEnforcementPoint" in pep_code
    assert "def can_manage_document" in pep_code
    assert "def is_safe_upload" in input_controls_code
    assert "def is_suspicious_search_query" in input_controls_code
    assert "def build_storage_key" in storage_code
    assert "def get_user_storage_usage_bytes" in storage_code
    assert "bandit -q -r web/app" in ci_workflow
    assert "pip-audit -r web/requirements.lock --strict" in ci_workflow