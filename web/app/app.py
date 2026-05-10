import functools
import pathlib
import os
import psycopg2
import flask
import dotenv
from . import db
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

dotenv.load_dotenv()

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

UPLOAD_FOLDER = "uploads"
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES"))
DISALLOWED_UPLOAD_EXTENSIONS = {
    ".bat",
    ".bin",
    ".cjs",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".htm",
    ".html",
    ".js",
    ".jsp",
    ".jspx",
    ".mjs",
    ".msi",
    ".php",
    ".php3",
    ".php4",
    ".php5",
    ".phtml",
    ".pl",
    ".py",
    ".pyc",
    ".rb",
    ".sh",
    ".svg",
    ".war",
}

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

def extract_metadata(filename):
    path = pathlib.Path(filename)
    stats = path.stat()
    return f"size={stats.st_size}, modified={stats.st_mtime}"

def is_safe_upload(filename):
    sanitized_name = secure_filename(filename or "")
    if not sanitized_name:
        return False, "Invalid file name."

    extension = pathlib.Path(sanitized_name).suffix.lower()
    if extension in DISALLOWED_UPLOAD_EXTENSIONS:
        return False, "File type not allowed."

    return True, sanitized_name

def get_document_by_id(cur, document_id):
    cur.execute(
        """
        SELECT id, owner_id, title, filename, metadata
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

    if stored_password.startswith(("pbkdf2:", "scrypt:")):
        try:
            return check_password_hash(stored_password, provided_password)
        except ValueError:
            return False

    return stored_password == provided_password

def is_admin_session():
    return flask.session.get("username") == "admin"

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
        SELECT id, username, is_disabled
        FROM users
        ORDER BY id ASC
        """
    )
    return cur.fetchall()

def get_user_by_id(cur, user_id):
    cur.execute(
        """
        SELECT id, username, is_disabled
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

def register_routes(app):

    @app.route("/")
    def index():
        if flask.session.get("user_id"):
            return flask.redirect(flask.url_for("documents_page"))
        return flask.redirect(flask.url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():

        if flask.request.method == "POST":
            username = flask.request.form.get("username", "")
            password = flask.request.form.get("password", "")

            conn = get_db()
            cur = conn.cursor()

            user = db.get_user_by_username(cur, username)

            cur.close()
            conn.close()

            if user and verify_password(user[2], password) and not user[3]:
                flask.session.clear()
                flask.session["user_id"] = user[0]
                flask.session["username"] = user[1]
                return flask.redirect(flask.url_for("documents_page"))

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
            return "Forbidden", 403

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
            "metadata": row[4],
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
        if not (is_admin_session() or user_id == owner_id):
            cur.close()
            conn.close()
            return "Forbidden", 403

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
            conn.commit()

        cur.close()
        conn.close()
        return flask.redirect(flask.url_for("document_details", document_id=document_id))

    @app.route("/documents/<int:document_id>/revoke", methods=["POST"])
    @login_required
    def revoke_document_share(document_id):
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
        if not (is_admin_session() or user_id == owner_id):
            cur.close()
            conn.close()
            return "Forbidden", 403

        cur.execute(
            """
            DELETE FROM document_shares
            WHERE document_id = %s AND shared_with = %s
            """,
            (document_id, shared_with),
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
            return "Forbidden", 403

        stored_filename = secure_filename(row[3])
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
            download_name=stored_filename,
        )

    @app.route("/documents")
    @login_required
    def documents_page():
        current_user_id = flask.session.get("user_id")

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

        return flask.render_template(
            "documents.html",
            documents=documents,
            requested_user_id=current_user_id,
            current_user_id=current_user_id,
            username=flask.session.get("username"),
        )

    @app.route("/shared")
    @login_required
    def shared_documents_page():
        current_user_id = flask.session.get("user_id")

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

        return flask.render_template(
            "shared.html",
            documents=documents,
            current_user_id=current_user_id,
            username=flask.session.get("username"),
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
                "is_disabled": row[2],
            }
            for row in rows
        ]

        return flask.render_template("users.html", users=users)

    @app.route("/admin/users/<int:user_id>/enable", methods=["POST"])
    @login_required
    def enable_user(user_id):
        if not is_admin_session():
            return "Forbidden", 403

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
        conn.commit()

        cur.close()
        conn.close()
        return flask.redirect(flask.url_for("admin_users_page"))

    @app.route("/admin/users/<int:user_id>/disable", methods=["POST"])
    @login_required
    def disable_user(user_id):
        if not is_admin_session():
            return "Forbidden", 403

        conn = get_db()
        cur = conn.cursor()

        target = get_user_by_id(cur, user_id)
        if not target:
            cur.close()
            conn.close()
            return "User not found", 404

        target_username = target[1]
        current_username = flask.session.get("username")

        if target_username == current_username:
            cur.close()
            conn.close()
            return "Cannot disable current admin user", 400

        if target_username == "admin":
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
            return "Forbidden", 403

        stored_filename = secure_filename(row[3])
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
            download_name=stored_filename,
        )

    @app.route("/documents/upload", methods=["POST"])
    @login_required
    def upload_document():
        user_id = flask.session.get("user_id")
        title = flask.request.form.get("title", "Untitled").strip() or "Untitled"
        uploaded_file = flask.request.files.get("document")

        if not uploaded_file or uploaded_file.filename == "":
            flask.flash("Please choose a file.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        is_valid_upload, sanitized_or_message = is_safe_upload(uploaded_file.filename)
        if not is_valid_upload:
            flask.flash(sanitized_or_message, "error")
            return flask.redirect(flask.url_for("documents_page"))

        filename = sanitized_or_message
        uploaded_file.stream.seek(0, os.SEEK_END)
        file_size = uploaded_file.stream.tell()
        uploaded_file.stream.seek(0)

        if file_size > app.config["MAX_UPLOAD_BYTES"]:
            flask.flash("File too large.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        upload_folder = BASE_DIR / app.config["UPLOAD_FOLDER"]
        upload_folder.mkdir(parents=True, exist_ok=True)

        destination = upload_folder / filename
        uploaded_file.save(destination)
        metadata = extract_metadata(destination)

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO documents (owner_id, title, filename, metadata)
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, title, filename, metadata),
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