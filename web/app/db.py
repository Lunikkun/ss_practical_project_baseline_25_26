import os
import threading
from contextlib import contextmanager
from typing import Any

import psycopg2

from .models import DocumentListItem, DocumentRecord, UserAdmin, UserAuth, UserBasic


DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")


_schema_lock = threading.Lock()
_document_hash_column_ready = False


def configure(settings):
    global DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
    DB_HOST = settings.db_host
    DB_PORT = settings.db_port
    DB_USER = settings.db_user
    DB_PASSWORD = settings.db_password
    DB_NAME = settings.db_name


def _map_user_auth(row) -> UserAuth | None:
    if not row:
        return None
    return {
        "id": row[0],
        "username": row[1],
        "password": row[2],
        "role": row[3],
        "is_disabled": row[4],
    }


def _map_user_admin(row) -> UserAdmin | None:
    if not row:
        return None
    return {
        "id": row[0],
        "username": row[1],
        "role": row[2],
        "is_disabled": row[3],
    }


def _map_user_basic(row) -> UserBasic | None:
    if not row:
        return None
    return {"id": row[0], "username": row[1]}


def _map_document_record(row) -> DocumentRecord | None:
    if not row:
        return None
    return {
        "id": row[0],
        "owner_id": row[1],
        "title": row[2],
        "filename": row[3],
        "storage_key": row[4],
        "metadata": row[5],
        "document_hash": row[6],
    }


def _map_document_list_item(row) -> DocumentListItem:
    return {
        "id": row[0],
        "title": row[1],
        "filename": row[2],
        "uploaded_at": row[3],
    }


def get_db():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME,
    )


@contextmanager
def cursor_scope():
    conn = get_db()
    cur = conn.cursor()
    try:
        yield cur
    finally:
        cur.close()
        conn.close()


@contextmanager
def transaction_scope():
    conn = get_db()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def ensure_documents_hash_column(app=None):
    global _document_hash_column_ready
    if _document_hash_column_ready:
        return

    with _schema_lock:
        if _document_hash_column_ready:
            return
        conn = None
        cur = None
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                """
                ALTER TABLE documents
                ADD COLUMN IF NOT EXISTS document_hash VARCHAR(64)
                """
            )
            conn.commit()
            _document_hash_column_ready = True
        except Exception:
            if conn:
                conn.rollback()
            if app:
                app.logger.exception("Failed to ensure documents.document_hash column")
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()


def get_user_by_username(cur, username):
    cur.execute(
        "SELECT id, username, password, role, is_disabled FROM users WHERE username=%s",
        (username,),
    )
    return _map_user_auth(cur.fetchone())


def get_documents_for_user(cur, owner_id):
    query = """
        SELECT id,title,filename,uploaded_at
        FROM documents
        WHERE owner_id=%s
        ORDER BY uploaded_at DESC
    """
    cur.execute(query, (owner_id,))
    return [_map_document_list_item(row) for row in cur.fetchall()]


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
    return [_map_document_list_item(row) for row in cur.fetchall()]


def get_document_by_id(cur, document_id):
    cur.execute(
        """
        SELECT id, owner_id, title, filename, storage_key, metadata, document_hash
        FROM documents
        WHERE id = %s
        """,
        (document_id,),
    )
    return _map_document_record(cur.fetchone())


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


def get_users(cur):
    cur.execute(
        """
        SELECT id, username
        FROM users
        ORDER BY username ASC
        """
    )
    return [_map_user_basic(row) for row in cur.fetchall()]


def get_all_users(cur):
    cur.execute(
        """
        SELECT id, username, role, is_disabled
        FROM users
        ORDER BY id ASC
        """
    )
    return [_map_user_admin(row) for row in cur.fetchall()]


def get_user_by_id(cur, user_id):
    cur.execute(
        """
        SELECT id, username, role, is_disabled
        FROM users
        WHERE id = %s
        """,
        (user_id,),
    )
    return _map_user_admin(cur.fetchone())


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
    return [_map_user_basic(row) for row in cur.fetchall()]


def write_audit_log(
    cur,
    *,
    actor_id,
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
            actor_id,
            action_type,
            target_user_id,
            target_document_id,
            (justification or "").strip(),
            result,
        ),
    )


def user_exists(cur, user_id):
    cur.execute(
        """
        SELECT id
        FROM users
        WHERE id = %s
        """,
        (user_id,),
    )
    return cur.fetchone() is not None


def is_document_shared_with(cur, document_id, user_id):
    cur.execute(
        """
        SELECT 1
        FROM document_shares
        WHERE document_id = %s AND shared_with = %s
        """,
        (document_id, user_id),
    )
    return cur.fetchone() is not None


def share_document_with_user(cur, document_id, user_id):
    cur.execute(
        """
        INSERT INTO document_shares (document_id, shared_with)
        VALUES (%s, %s)
        """,
        (document_id, user_id),
    )


def revoke_document_share_for_user(cur, document_id, user_id):
    cur.execute(
        """
        DELETE FROM document_shares
        WHERE document_id = %s AND shared_with = %s
        """,
        (document_id, user_id),
    )
    return cur.rowcount > 0


def update_document_hash(cur, document_id, document_hash):
    cur.execute(
        """
        UPDATE documents
        SET document_hash = %s
        WHERE id = %s
        """,
        (document_hash, document_id),
    )


def insert_document(cur, owner_id, title, filename, storage_key, document_hash, metadata):
    cur.execute(
        """
        INSERT INTO documents (owner_id, title, filename, storage_key, document_hash, metadata)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (owner_id, title, filename, storage_key, document_hash, metadata),
    )


def set_user_disabled(cur, user_id, disabled):
    cur.execute(
        """
        UPDATE users
        SET is_disabled = %s
        WHERE id = %s
        """,
        (disabled, user_id),
    )


def health_check(cur):
    cur.execute("SELECT 1")
