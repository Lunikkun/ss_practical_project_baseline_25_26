import threading
import time

import flask

from .common import build_session_fingerprint, verify_password
from ..services import auth_service


auth_bp = flask.Blueprint("auth", __name__)

_auth_lock = threading.Lock()
_ip_rate_state: dict = {}
_account_lock_state: dict = {}


@auth_bp.route("/")
def index():
    if flask.session.get("user_id"):
        return flask.redirect(flask.url_for("documents.documents_page"))
    return flask.redirect(flask.url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    settings = flask.current_app.config["APP_SETTINGS"]

    if flask.request.method == "POST":
        username = flask.request.form.get("username", "").strip()
        password = flask.request.form.get("password", "")
        client_ip = flask.request.remote_addr or "unknown"
        now = time.time()

        with _auth_lock:
            ip_entry = _ip_rate_state.setdefault(client_ip, {"count": 0, "window_start": now})
            if now - ip_entry["window_start"] > settings.login_ip_rate_window:
                ip_entry["count"] = 0
                ip_entry["window_start"] = now
            ip_entry["count"] += 1
            ip_rate_exceeded = ip_entry["count"] > settings.login_ip_rate_limit

        if ip_rate_exceeded:
            flask.flash("Too many requests. Please try again later.", "error")
            return flask.render_template("login.html"), 429

        with _auth_lock:
            acc_entry = _account_lock_state.get(username)
            account_locked = acc_entry is not None and acc_entry["locked_until"] > now

        if account_locked:
            flask.flash("Account temporarily locked. Try again later.", "error")
            return flask.render_template("login.html"), 429

        user = auth_service.get_login_user(username)

        dummy_hash = "pbkdf2:sha256:600000$dummy$" + "a" * 64
        candidate_hash = user["password"] if user else dummy_hash
        password_ok = verify_password(candidate_hash, password)

        if user and password_ok and not user["is_disabled"]:
            with _auth_lock:
                _account_lock_state.pop(username, None)
            flask.session.clear()
            flask.session["user_id"] = user["id"]
            flask.session["username"] = user["username"]
            flask.session["role"] = user["role"]
            flask.session["session_fp"] = build_session_fingerprint()
            return flask.redirect(flask.url_for("documents.documents_page"))

        with _auth_lock:
            acc = _account_lock_state.setdefault(username, {"failures": 0, "locked_until": 0.0})
            acc["failures"] += 1
            if acc["failures"] >= settings.login_lockout_threshold:
                acc["locked_until"] = time.time() + settings.login_lockout_duration
                acc["failures"] = 0

        flask.flash("Invalid credentials.", "error")

    return flask.render_template("login.html")


@auth_bp.route("/logout")
def logout():
    flask.session.clear()
    return flask.redirect(flask.url_for("auth.login"))
