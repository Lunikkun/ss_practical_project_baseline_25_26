import dotenv
import flask
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException

from . import db
from .config import AppSettings
from .routes.admin import admin_bp
from .routes.auth import auth_bp
from .routes.common import BASE_DIR, build_session_fingerprint
from .routes.documents import documents_bp
from .routes.system import system_bp
from .services import auth_service


dotenv.load_dotenv()


def create_app():
    settings = AppSettings.from_env()

    app = flask.Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    app.secret_key = settings.secret_key
    app.config["APP_SETTINGS"] = settings
    app.config["UPLOAD_FOLDER"] = settings.upload_folder
    app.config["MAX_CONTENT_LENGTH"] = settings.max_upload_bytes
    app.config["MAX_UPLOAD_BYTES"] = settings.max_upload_bytes
    app.config["WTF_CSRF_TIME_LIMIT"] = None
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = settings.session_cookie_samesite
    app.config["SESSION_COOKIE_SECURE"] = settings.session_cookie_secure
    if app.config["SESSION_COOKIE_SECURE"]:
        app.config["SESSION_COOKIE_NAME"] = "__Host-session"
    app.config["FORCE_HTTPS"] = settings.force_https
    app.config["HSTS_MAX_AGE"] = settings.hsts_max_age
    app.config["APP_SECURITY_PROFILE"] = settings.app_security_profile

    if app.config["APP_SECURITY_PROFILE"] == "production":
        if not app.config["SESSION_COOKIE_SECURE"]:
            raise RuntimeError("Production security profile requires SESSION_COOKIE_SECURE=1.")
        if not app.config["FORCE_HTTPS"]:
            raise RuntimeError("Production security profile requires FORCE_HTTPS=1.")

    db.configure(settings)
    db.ensure_documents_hash_column(app)

    CSRFProtect(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(system_bp)

    register_global_handlers(app)

    return app


def register_global_handlers(app):
    @app.before_request
    def enforce_https():
        if not app.config.get("FORCE_HTTPS"):
            return
        if flask.request.path == "/health":
            return

        proto = flask.request.headers.get("X-Forwarded-Proto", "http")
        if flask.request.is_secure or proto == "https":
            return

        secure_url = flask.request.url.replace("http://", "https://", 1)
        return flask.redirect(secure_url, code=301)

    @app.before_request
    def check_user_disabled():
        if "user_id" not in flask.session:
            return

        expected_fingerprint = flask.session.get("session_fp")
        current_fingerprint = build_session_fingerprint()
        if not expected_fingerprint or expected_fingerprint != current_fingerprint:
            flask.session.clear()
            flask.flash("Session invalidated. Please log in again.", "error")
            return flask.redirect(flask.url_for("auth.login"))

        user = auth_service.get_user_by_id(flask.session["user_id"])
        if user and user["is_disabled"]:
            flask.session.clear()
            return flask.redirect(flask.url_for("auth.login"))

    @app.errorhandler(Exception)
    def handle_unexpected_exception(error):
        if isinstance(error, HTTPException):
            return error
        app.logger.exception("Unhandled application exception path=%s", flask.request.path)
        return flask.render_template("error_generic.html"), 500

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), autoplay=(), camera=(), display-capture=(), "
            "encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), midi=(), payment=(), usb=()"
        )
        response.headers["Strict-Transport-Security"] = (
            f"max-age={app.config['HSTS_MAX_AGE']}; includeSubDomains"
        )

        if not flask.request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response
