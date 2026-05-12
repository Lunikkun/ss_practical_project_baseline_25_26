import functools
import pathlib
import os
import hashlib
import shutil
import threading
import time
import psycopg2
import flask
import dotenv
from flask_wtf.csrf import CSRFProtect
from . import db
from .security.pep import PolicyEnforcementPoint
from .security.input_controls import (
    is_safe_document_title,
    is_safe_upload,
    is_suspicious_search_query,
    normalize_search_query,
)
from .services.storage_service import (
    build_storage_key,
    extract_metadata,
    get_total_storage_usage_bytes,
    get_user_storage_usage_bytes,
)
from werkzeug.security import check_password_hash
from werkzeug.exceptions import HTTPException

dotenv.load_dotenv()

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

UPLOAD_FOLDER = "uploads"
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES"))

# Brute force protection
_auth_lock = threading.Lock()
_ip_rate_state: dict = {}      # ip → {"count": int, "window_start": float}
_account_lock_state: dict = {} # username → {"failures": int, "locked_until": float}
_upload_lock = threading.Lock()
_upload_rate_state: dict = {}  # user_id -> {"count": int, "window_start": float}

LOGIN_IP_RATE_LIMIT = int(os.getenv("LOGIN_IP_RATE_LIMIT", "50"))        # requests per minute per IP
LOGIN_IP_RATE_WINDOW = 60                                                   # seconds
LOGIN_LOCKOUT_THRESHOLD = int(os.getenv("LOGIN_LOCKOUT_THRESHOLD", "5"))  # failures before lockout
LOGIN_LOCKOUT_DURATION = int(os.getenv("LOGIN_LOCKOUT_DURATION", "300"))  # lockout seconds (5 min)
FORCE_HTTPS = os.getenv("FORCE_HTTPS", "0") == "1"
HSTS_MAX_AGE = int(os.getenv("HSTS_MAX_AGE", "31536000"))
APP_SECURITY_PROFILE = os.getenv("APP_SECURITY_PROFILE", "dev").lower()
UPLOAD_RATE_LIMIT = int(os.getenv("UPLOAD_RATE_LIMIT", "25"))
UPLOAD_RATE_WINDOW = int(os.getenv("UPLOAD_RATE_WINDOW", "60"))
USER_MAX_FILES = int(os.getenv("USER_MAX_FILES", "0"))
USER_STORAGE_QUOTA_BYTES = int(os.getenv("USER_STORAGE_QUOTA_BYTES", "0"))
GLOBAL_STORAGE_QUOTA_BYTES = int(os.getenv("GLOBAL_STORAGE_QUOTA_BYTES", "0"))
MIN_FREE_DISK_BYTES = int(os.getenv("MIN_FREE_DISK_BYTES", "10485760"))

def get_db():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME,
    )

def create_app():
    app = flask.Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    app.secret_key = os.getenv("SECRET_KEY")
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.config["MAX_UPLOAD_BYTES"] = MAX_UPLOAD_BYTES
    app.config["WTF_CSRF_TIME_LIMIT"] = None
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    secure_cookie_from_env = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
    app.config["SESSION_COOKIE_SECURE"] = secure_cookie_from_env or FORCE_HTTPS
    if app.config["SESSION_COOKIE_SECURE"]:
        app.config["SESSION_COOKIE_NAME"] = "__Host-session"
    app.config["FORCE_HTTPS"] = FORCE_HTTPS
    app.config["HSTS_MAX_AGE"] = HSTS_MAX_AGE
    app.config["APP_SECURITY_PROFILE"] = APP_SECURITY_PROFILE

    if app.config["APP_SECURITY_PROFILE"] == "production":
        if not app.config["SESSION_COOKIE_SECURE"]:
            raise RuntimeError("Production security profile requires SESSION_COOKIE_SECURE=1.")
        if not app.config["FORCE_HTTPS"]:
            raise RuntimeError("Production security profile requires FORCE_HTTPS=1.")

    CSRFProtect(app)
    register_routes(app)

    return app

def get_documents_for_user(cur, owner_id):
    query = """
        SELECT id,title,filename,uploaded_at
        FROM documents
        WHERE owner_id=%s
        ORDER BY uploaded_at DESC
    """
    cur.execute(query, (owner_id,))
    return cur.fetchall()

def get_shared_documents_for_user(cur, user_id):
    cur.execute(
        """
        SELECT d.id, d.title, d.filename, d.uploaded_at
        FROM documents d
        JOIN document_shares s ON s.document_id = d.id
        WHERE s.shared_with = %s
        ORDER BY d.uploaded_at DESC
        """,
        (user_id,),
    )
    return cur.fetchall()


def get_document_by_id(cur, document_id):
    cur.execute(
        """
        SELECT id, owner_id, title, filename, storage_key, metadata
        FROM documents
        WHERE id = %s
        """,
        (document_id,),
    )
    return cur.fetchone()

def can_access_document(cur, document_id, user_id):
    cur.execute(
        """
        SELECT 1
        FROM documents d
        LEFT JOIN document_shares s ON s.document_id = d.id AND s.shared_with = %s
        WHERE d.id = %s AND (d.owner_id = %s OR s.id IS NOT NULL)
        """,
        (user_id, document_id, user_id),
    )
    return cur.fetchone() is not None

def can_access_shared_document(cur, document_id, user_id):
    cur.execute(
        """
        SELECT 1
        FROM document_shares
        WHERE document_id = %s AND shared_with = %s
        """,
        (document_id, user_id),
    )
    return cur.fetchone() is not None

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


def is_reviewer_session():
    return flask.session.get("role") == "reviewer"

def get_users(cur):
    cur.execute(
        """
        SELECT id, username
        FROM users
        ORDER BY username ASC
        """
    )
    return cur.fetchall()

def get_all_users(cur):
    cur.execute(
        """
        SELECT id, username, role, is_disabled
        FROM users
        ORDER BY id ASC
        """
    )
    return cur.fetchall()

def get_user_by_id(cur, user_id):
    cur.execute(
        """
        SELECT id, username, role, is_disabled
        FROM users
        WHERE id = %s
        """,
        (user_id,),
    )
    return cur.fetchone()

def get_share_recipients_for_document(cur, document_id):
    cur.execute(
        """
        SELECT u.id, u.username
        FROM document_shares s
        JOIN users u ON u.id = s.shared_with
        WHERE s.document_id = %s
        ORDER BY u.username ASC
        """,
        (document_id,),
    )
    return [{"id": row[0], "username": row[1]} for row in cur.fetchall()]

def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in flask.session:
            flask.flash("Please log in first.", "error")
            return flask.redirect(flask.url_for("login"))
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


def register_routes(app):

    def log_denied_document_access(action: str, document_id: int, status_code: int):
        app.logger.warning(
            "Denied document access action=%s doc_id=%s user_id=%s ip=%s status=%s",
            action,
            document_id,
            flask.session.get("user_id", "anonymous"),
            get_client_ip(),
            status_code,
        )

    def write_audit_log(
        cur,
        *,
        action_type: str,
        result: str,
        target_user_id=None,
        target_document_id=None,
        justification: str = "",
    ):
        cur.execute(
            """
            INSERT INTO audit_logs (
                actor_id,
                action_type,
                target_user_id,
                target_document_id,
                justification,
                result
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                flask.session.get("user_id"),
                action_type,
                target_user_id,
                target_document_id,
                (justification or "").strip(),
                result,
            ),
        )

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
            return flask.redirect(flask.url_for("login"))

        conn = get_db()
        cur = conn.cursor()
        user = get_user_by_id(cur, flask.session["user_id"])
        cur.close()
        conn.close()
        if user and user[3]:
            flask.session.clear()
            return flask.redirect(flask.url_for("login"))

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
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        response.headers["Strict-Transport-Security"] = f"max-age={app.config['HSTS_MAX_AGE']}; includeSubDomains"

        # Avoid serving stale authenticated content after permission revocation.
        if flask.session.get("user_id"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response

    @app.route("/")
    def index():
        if flask.session.get("user_id"):
            return flask.redirect(flask.url_for("documents_page"))
        return flask.redirect(flask.url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():

        if flask.request.method == "POST":
            username = flask.request.form.get("username", "").strip()
            password = flask.request.form.get("password", "")
            client_ip = flask.request.remote_addr or "unknown"
            now = time.time()

            # --- IP-based rate limiting ---
            with _auth_lock:
                ip_entry = _ip_rate_state.setdefault(
                    client_ip, {"count": 0, "window_start": now}
                )
                if now - ip_entry["window_start"] > LOGIN_IP_RATE_WINDOW:
                    ip_entry["count"] = 0
                    ip_entry["window_start"] = now
                ip_entry["count"] += 1
                ip_rate_exceeded = ip_entry["count"] > LOGIN_IP_RATE_LIMIT

            if ip_rate_exceeded:
                flask.flash("Too many requests. Please try again later.", "error")
                return flask.render_template("login.html"), 429

            # --- Account lockout check ---
            with _auth_lock:
                acc_entry = _account_lock_state.get(username)
                account_locked = acc_entry is not None and acc_entry["locked_until"] > now

            if account_locked:
                flask.flash("Account temporarily locked. Try again later.", "error")
                return flask.render_template("login.html"), 429

            # --- Authentication (constant-time: always query DB and always verify) ---
            conn = get_db()
            cur = conn.cursor()
            user = db.get_user_by_username(cur, username)
            cur.close()
            conn.close()

            # Always call verify_password to prevent timing-based user enumeration
            dummy_hash = "pbkdf2:sha256:600000$dummy$" + "a" * 64
            candidate_hash = user[2] if user else dummy_hash
            password_ok = verify_password(candidate_hash, password)

            if user and password_ok and not user[4]:
                with _auth_lock:
                    _account_lock_state.pop(username, None)
                flask.session.clear()
                flask.session["user_id"] = user[0]
                flask.session["username"] = user[1]
                flask.session["role"] = user[3]
                flask.session["session_fp"] = build_session_fingerprint()
                return flask.redirect(flask.url_for("documents_page"))

            # --- Track failed attempt ---
            with _auth_lock:
                acc = _account_lock_state.setdefault(
                    username, {"failures": 0, "locked_until": 0.0}
                )
                acc["failures"] += 1
                if acc["failures"] >= LOGIN_LOCKOUT_THRESHOLD:
                    acc["locked_until"] = time.time() + LOGIN_LOCKOUT_DURATION
                    acc["failures"] = 0

            flask.flash("Invalid credentials.", "error")

        return flask.render_template("login.html")

    @app.route("/logout")
    def logout():
        flask.session.clear()
        return flask.redirect(flask.url_for("login"))

    @app.route("/documents/<int:document_id>")
    @login_required
    def document_details(document_id):
        user_id = flask.session.get("user_id")
        conn = get_db()
        cur = conn.cursor()

        row = get_document_by_id(cur, document_id)
        if row and not can_access_document(cur, document_id, user_id):
            cur.close()
            conn.close()
            log_denied_document_access("details", document_id, 404)
            return "Document not found", 404

        users = get_users(cur) if row else []
        share_recipients = get_share_recipients_for_document(cur, document_id) if row else []

        cur.close()
        conn.close()

        if not row:
            return "Document not found", 404

        document = {
            "id": row[0],
            "owner_id": row[1],
            "title": row[2],
            "filename": row[3],
            "metadata": row[5],
        }

        share_candidates = [
            {"id": user[0], "username": user[1]}
            for user in users
            if user[0] != row[1]
        ]
        can_share = is_admin_session() or user_id == row[1]

        return flask.render_template(
            "document_details.html",
            document=document,
            can_share=can_share,
            share_candidates=share_candidates,
            share_recipients=share_recipients,
        )

    @app.route("/documents/<int:document_id>/share", methods=["POST"])
    @login_required
    def share_document(document_id):
        if not PolicyEnforcementPoint.can_share_document(flask.session.get("role")):
            return "Forbidden", 403
        user_id = flask.session.get("user_id")
        shared_with_raw = flask.request.form.get("shared_with", "").strip()

        try:
            shared_with = int(shared_with_raw)
        except ValueError:
            return "Invalid target user", 400

        conn = get_db()
        cur = conn.cursor()

        row = get_document_by_id(cur, document_id)
        if not row:
            cur.close()
            conn.close()
            return "Document not found", 404

        owner_id = row[1]
        if not PolicyEnforcementPoint.can_manage_document(
            actor_id=user_id,
            actor_role=flask.session.get("role"),
            owner_id=owner_id,
        ):
            write_audit_log(
                cur,
                action_type="share_document",
                result="denied_not_owner_or_admin",
                target_user_id=shared_with,
                target_document_id=document_id,
            )
            conn.commit()
            cur.close()
            conn.close()
            log_denied_document_access("share", document_id, 404)
            return "Document not found", 404

        if shared_with == owner_id:
            cur.close()
            conn.close()
            return "Cannot share with owner", 400

        cur.execute(
            """
            SELECT id
            FROM users
            WHERE id = %s
            """,
            (shared_with,),
        )
        target_user = cur.fetchone()
        if not target_user:
            cur.close()
            conn.close()
            return "Target user not found", 404

        cur.execute(
            """
            SELECT 1
            FROM document_shares
            WHERE document_id = %s AND shared_with = %s
            """,
            (document_id, shared_with),
        )
        already_shared = cur.fetchone() is not None
        if not already_shared:
            cur.execute(
                """
                INSERT INTO document_shares (document_id, shared_with)
                VALUES (%s, %s)
                """,
                (document_id, shared_with),
            )
            write_audit_log(
                cur,
                action_type="share_document",
                result="success",
                target_user_id=shared_with,
                target_document_id=document_id,
            )
            conn.commit()
        else:
            write_audit_log(
                cur,
                action_type="share_document",
                result="noop_already_shared",
                target_user_id=shared_with,
                target_document_id=document_id,
            )
            conn.commit()

        cur.close()
        conn.close()
        return flask.redirect(flask.url_for("document_details", document_id=document_id))

    @app.route("/documents/<int:document_id>/revoke", methods=["POST"])
    @login_required
    def revoke_document_share(document_id):
        if not PolicyEnforcementPoint.can_share_document(flask.session.get("role")):
            return "Forbidden", 403
        user_id = flask.session.get("user_id")
        shared_with_raw = flask.request.form.get("shared_with", "").strip()

        try:
            shared_with = int(shared_with_raw)
        except ValueError:
            return "Invalid target user", 400

        conn = get_db()
        cur = conn.cursor()

        row = get_document_by_id(cur, document_id)
        if not row:
            cur.close()
            conn.close()
            return "Document not found", 404

        owner_id = row[1]
        if not PolicyEnforcementPoint.can_manage_document(
            actor_id=user_id,
            actor_role=flask.session.get("role"),
            owner_id=owner_id,
        ):
            write_audit_log(
                cur,
                action_type="revoke_document_share",
                result="denied_not_owner_or_admin",
                target_user_id=shared_with,
                target_document_id=document_id,
            )
            conn.commit()
            cur.close()
            conn.close()
            log_denied_document_access("revoke", document_id, 404)
            return "Document not found", 404

        cur.execute(
            """
            DELETE FROM document_shares
            WHERE document_id = %s AND shared_with = %s
            """,
            (document_id, shared_with),
        )
        write_audit_log(
            cur,
            action_type="revoke_document_share",
            result="success" if cur.rowcount > 0 else "noop_not_shared",
            target_user_id=shared_with,
            target_document_id=document_id,
        )
        conn.commit()

        cur.close()
        conn.close()
        return flask.redirect(flask.url_for("document_details", document_id=document_id))

    @app.route("/documents/<int:document_id>/download")
    @login_required
    def download_document(document_id):
        user_id = flask.session.get("user_id")

        conn = get_db()
        cur = conn.cursor()

        row = get_document_by_id(cur, document_id)
        if not row:
            cur.close()
            conn.close()
            return "Document not found", 404

        if not can_access_document(cur, document_id, user_id):
            cur.close()
            conn.close()
            log_denied_document_access("download", document_id, 404)
            return "Document not found", 404

        stored_filename = row[4]
        download_filename = row[3]
        cur.close()
        conn.close()

        upload_folder = BASE_DIR / app.config["UPLOAD_FOLDER"]
        file_path = upload_folder / stored_filename
        if not file_path.exists() or not file_path.is_file():
            return "Document file not found", 404

        return flask.send_from_directory(
            str(upload_folder),
            stored_filename,
            as_attachment=True,
            download_name=download_filename,
        )

    @app.route("/documents")
    @login_required
    def documents_page():
        current_user_id = flask.session.get("user_id")
        search_query = normalize_search_query(flask.request.args.get("search", ""))

        if search_query and is_suspicious_search_query(search_query):
            app.logger.warning(
                "Blocked suspicious search payload user_id=%s ip=%s query=%r",
                current_user_id,
                get_client_ip(),
                search_query,
            )
            return "Invalid search query", 400

        conn = get_db()
        cur = conn.cursor()

        docs = get_documents_for_user(cur, current_user_id)

        cur.close()
        conn.close()

        documents = [
            {
                "id": d[0],
                "title": d[1],
                "filename": d[2],
                "uploaded_at": d[3],
            }
            for d in docs
        ]

        if search_query:
            search_lower = search_query.lower()
            documents = [
                d for d in documents if search_lower in d["title"].lower() or search_lower in d["filename"].lower()
            ]

        return flask.render_template(
            "documents.html",
            documents=documents,
            requested_user_id=current_user_id,
            current_user_id=current_user_id,
            username=flask.session.get("username"),
            search_query=search_query,
        )

    @app.route("/shared")
    @login_required
    def shared_documents_page():
        current_user_id = flask.session.get("user_id")
        search_query = normalize_search_query(flask.request.args.get("search", ""))

        if search_query and is_suspicious_search_query(search_query):
            app.logger.warning(
                "Blocked suspicious shared-search payload user_id=%s ip=%s query=%r",
                current_user_id,
                get_client_ip(),
                search_query,
            )
            return "Invalid search query", 400

        conn = get_db()
        cur = conn.cursor()
        shared_docs = get_shared_documents_for_user(cur, current_user_id)
        cur.close()
        conn.close()

        documents = [
            {
                "id": d[0],
                "title": d[1],
                "filename": d[2],
                "uploaded_at": d[3],
            }
            for d in shared_docs
        ]

        if search_query:
            search_lower = search_query.lower()
            documents = [
                d for d in documents if search_lower in d["title"].lower() or search_lower in d["filename"].lower()
            ]

        return flask.render_template(
            "shared.html",
            documents=documents,
            current_user_id=current_user_id,
            username=flask.session.get("username"),
            search_query=search_query,
        )

    @app.route("/admin/users")
    @login_required
    def admin_users_page():
        if not is_admin_session():
            return "Forbidden", 403

        conn = get_db()
        cur = conn.cursor()
        rows = get_all_users(cur)
        cur.close()
        conn.close()

        users = [
            {
                "id": row[0],
                "username": row[1],
                "role": row[2],
                "is_disabled": row[3],
            }
            for row in rows
        ]

        return flask.render_template("users.html", users=users)

    @app.route("/admin/users/<int:user_id>/enable", methods=["POST"])
    @login_required
    def enable_user(user_id):
        if not is_admin_session():
            return "Forbidden", 403

        justification = flask.request.form.get("justification", "").strip()
        if not justification:
            return "Justification is required", 400

        conn = get_db()
        cur = conn.cursor()

        target = get_user_by_id(cur, user_id)
        if not target:
            cur.close()
            conn.close()
            return "User not found", 404

        cur.execute(
            """
            UPDATE users
            SET is_disabled = FALSE
            WHERE id = %s
            """,
            (user_id,),
        )
        write_audit_log(
            cur,
            action_type="enable_user",
            result="success",
            target_user_id=user_id,
            justification=justification,
        )
        conn.commit()

        cur.close()
        conn.close()
        return flask.redirect(flask.url_for("admin_users_page"))

    @app.route("/admin/users/<int:user_id>/disable", methods=["POST"])
    @login_required
    def disable_user(user_id):
        if not is_admin_session():
            return "Forbidden", 403

        justification = flask.request.form.get("justification", "").strip()
        if not justification:
            return "Justification is required", 400

        conn = get_db()
        cur = conn.cursor()

        target = get_user_by_id(cur, user_id)
        if not target:
            cur.close()
            conn.close()
            return "User not found", 404

        target_username = target[1]
        target_role = target[2]
        current_username = flask.session.get("username")

        if target_username == current_username:
            cur.close()
            conn.close()
            return "Cannot disable current admin user", 400

        if target_role == "admin":
            cur.close()
            conn.close()
            return "Cannot disable admin account", 400

        cur.execute(
            """
            UPDATE users
            SET is_disabled = TRUE
            WHERE id = %s
            """,
            (user_id,),
        )
        write_audit_log(
            cur,
            action_type="disable_user",
            result="success",
            target_user_id=user_id,
            justification=justification,
        )
        conn.commit()

        cur.close()
        conn.close()
        return flask.redirect(flask.url_for("admin_users_page"))

    @app.route("/shared/<int:document_id>/download")
    @login_required
    def download_shared_document(document_id):
        user_id = flask.session.get("user_id")

        conn = get_db()
        cur = conn.cursor()

        row = get_document_by_id(cur, document_id)
        if not row:
            cur.close()
            conn.close()
            return "Document not found", 404

        if not can_access_shared_document(cur, document_id, user_id):
            cur.close()
            conn.close()
            log_denied_document_access("shared_download", document_id, 404)
            return "Document not found", 404

        stored_filename = row[4]
        download_filename = row[3]
        cur.close()
        conn.close()

        upload_folder = BASE_DIR / app.config["UPLOAD_FOLDER"]
        file_path = upload_folder / stored_filename
        if not file_path.exists() or not file_path.is_file():
            return "Document file not found", 404

        return flask.send_from_directory(
            str(upload_folder),
            stored_filename,
            as_attachment=True,
            download_name=download_filename,
        )

    @app.route("/documents/upload", methods=["POST"])
    @login_required
    def upload_document():
        user_id = flask.session.get("user_id")
        title = flask.request.form.get("title", "Untitled").strip() or "Untitled"
        uploaded_file = flask.request.files.get("document")

        now = time.time()
        with _upload_lock:
            rate_entry = _upload_rate_state.setdefault(user_id, {"count": 0, "window_start": now})
            if now - rate_entry["window_start"] > UPLOAD_RATE_WINDOW:
                rate_entry["count"] = 0
                rate_entry["window_start"] = now
            rate_entry["count"] += 1
            upload_rate_exceeded = rate_entry["count"] > UPLOAD_RATE_LIMIT

        if upload_rate_exceeded:
            app.logger.warning(
                "Upload rate limit exceeded user_id=%s ip=%s count=%s window=%s",
                user_id,
                get_client_ip(),
                UPLOAD_RATE_LIMIT,
                UPLOAD_RATE_WINDOW,
            )
            return "Too many upload requests. Please slow down.", 429

        if not is_safe_document_title(title):
            flask.flash("Invalid document title.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        if not uploaded_file or uploaded_file.filename == "":
            flask.flash("Please choose a file.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        is_valid_upload, sanitized_or_message = is_safe_upload(uploaded_file.filename)
        if not is_valid_upload:
            flask.flash(sanitized_or_message, "error")
            return flask.redirect(flask.url_for("documents_page"))

        filename = sanitized_or_message
        storage_key = build_storage_key(filename)
        upload_folder = BASE_DIR / app.config["UPLOAD_FOLDER"]
        upload_folder.mkdir(parents=True, exist_ok=True)
        os.chmod(upload_folder, 0o700)

        current_storage_usage = get_total_storage_usage_bytes(upload_folder)

        uploaded_file.stream.seek(0, os.SEEK_END)
        file_size = uploaded_file.stream.tell()
        uploaded_file.stream.seek(0)

        if file_size > app.config["MAX_UPLOAD_BYTES"]:
            flask.flash("File too large.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        if GLOBAL_STORAGE_QUOTA_BYTES > 0 and current_storage_usage + file_size > GLOBAL_STORAGE_QUOTA_BYTES:
            app.logger.warning(
                "Global storage quota exceeded user_id=%s ip=%s usage=%s requested=%s quota=%s",
                user_id,
                get_client_ip(),
                current_storage_usage,
                file_size,
                GLOBAL_STORAGE_QUOTA_BYTES,
            )
            return "Storage temporarily full. Please try again later.", 507

        disk_free_bytes = shutil.disk_usage(upload_folder).free
        if MIN_FREE_DISK_BYTES > 0 and disk_free_bytes < MIN_FREE_DISK_BYTES:
            app.logger.warning(
                "Low disk space upload blocked user_id=%s ip=%s free=%s threshold=%s",
                user_id,
                get_client_ip(),
                disk_free_bytes,
                MIN_FREE_DISK_BYTES,
            )
            return "Storage temporarily unavailable.", 507

        destination = upload_folder / storage_key

        conn = get_db()
        cur = conn.cursor()

        user_file_count, user_storage_usage = get_user_storage_usage_bytes(cur, user_id, upload_folder)
        if USER_MAX_FILES > 0 and user_file_count >= USER_MAX_FILES:
            cur.close()
            conn.close()
            app.logger.warning(
                "User file quota exceeded user_id=%s ip=%s count=%s quota=%s",
                user_id,
                get_client_ip(),
                user_file_count,
                USER_MAX_FILES,
            )
            return "Upload quota exceeded.", 429

        if USER_STORAGE_QUOTA_BYTES > 0 and user_storage_usage + file_size > USER_STORAGE_QUOTA_BYTES:
            cur.close()
            conn.close()
            app.logger.warning(
                "User storage quota exceeded user_id=%s ip=%s usage=%s requested=%s quota=%s",
                user_id,
                get_client_ip(),
                user_storage_usage,
                file_size,
                USER_STORAGE_QUOTA_BYTES,
            )
            return "Upload quota exceeded.", 429

        uploaded_file.save(destination)
        os.chmod(destination, 0o600)
        metadata = extract_metadata(destination)

        cur.execute(
            """
            INSERT INTO documents (owner_id, title, filename, storage_key, metadata)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, title, filename, storage_key, metadata),
        )
        conn.commit()

        cur.close()
        conn.close()

        return flask.redirect(flask.url_for("documents_page", uploaded=title))

    @app.route("/health")
    def health():
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
            conn.close()
            return {"status": "ok"}, 200
        except Exception:
            return {"status": "error"}, 500


    # ------------------------------------------------------------------
    # Planned / Not Yet Implemented Endpoints
    #
    # The following routes are part of the intended system interface and
    # are not implemented in the baseline version of the application.
    #
    # The expected behavior of these endpoints is summarized below.
    #
    # Document operations
    #
    #   GET  /documents/<id>/download
    #       Download the specified document.
    #       Success: returns file contents (HTTP 200)
    #       Errors: 404 if the document does not exist
    #
    #   POST /documents/<id>/share
    #       Share a document with another user.
    #       Form parameter:
    #           shared_with  -> target user id
    #       Success: redirect or confirmation (HTTP 302 or 200)
    #
    # Shared documents
    #
    #   GET  /shared
    #       Display documents that were shared with the current user.
    #       Success: HTTP 200
    #
    #   GET  /shared/<id>/download
    #       Download a document that was shared with the current user.
    #       Success: returns file contents (HTTP 200)
    #
    # Administration
    #
    #   GET  /admin/users
    #       Display a list of users in the system.
    #       Success: HTTP 200
    #
    #   POST /admin/users/<id>/enable
    #       Enable a user account.
    #       Success: redirect or confirmation (HTTP 302 or 200)
    #
    #   POST /admin/users/<id>/disable
    #       Disable a user account.
    #       Success: redirect or confirmation (HTTP 302 or 200)
    #
    # ------------------------------------------------------------------