import functools
import hashlib
import pathlib

import flask
from werkzeug.security import check_password_hash

from ..security.pep import PolicyEnforcementPoint

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in flask.session:
            flask.flash("Please log in first.", "error")
            return flask.redirect(flask.url_for("auth.login"))
        return fn(*args, **kwargs)

    return wrapper


def get_client_ip():
    forwarded_for = flask.request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return flask.request.remote_addr or "unknown"


def get_ip_bucket(ip_address: str) -> str:
    if "." in ip_address:
        parts = ip_address.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3])
    return ip_address


def build_session_fingerprint():
    ip_bucket = get_ip_bucket(get_client_ip())
    user_agent = flask.request.headers.get("User-Agent", "")
    raw_fingerprint = f"{ip_bucket}|{user_agent}"
    return hashlib.sha256(raw_fingerprint.encode("utf-8")).hexdigest()


def verify_password(stored_password, provided_password):
    if not stored_password:
        return False

    if not stored_password.startswith(("pbkdf2:", "scrypt:")):
        return False

    try:
        return check_password_hash(stored_password, provided_password)
    except ValueError:
        return False


def is_admin_session():
    return PolicyEnforcementPoint.can_access_admin(flask.session.get("role"))


def log_denied_document_access(action: str, document_id: int, status_code: int):
    flask.current_app.logger.warning(
        "Denied document access action=%s doc_id=%s user_id=%s ip=%s status=%s",
        action,
        document_id,
        flask.session.get("user_id", "anonymous"),
        get_client_ip(),
        status_code,
    )
