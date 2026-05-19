from .. import db


def get_document_details_view(document_id, user_id, is_admin):
    with db.cursor_scope() as cur:
        row = db.get_document_by_id(cur, document_id)
        if not row:
            return "not_found", None

        if not db.can_access_document(cur, document_id, user_id):
            return "forbidden", None

        users = db.get_users(cur)
        share_recipients = db.get_share_recipients_for_document(cur, document_id)

    document = {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "title": row["title"],
        "filename": row["filename"],
        "metadata": row["metadata"],
        "document_hash": row["document_hash"],
    }
    share_candidates = [
        {"id": user["id"], "username": user["username"]}
        for user in users
        if user["id"] != row["owner_id"]
    ]

    payload = {
        "document": document,
        "share_candidates": share_candidates,
        "share_recipients": share_recipients,
        "can_share": is_admin or user_id == row["owner_id"],
    }
    return "ok", payload


def list_owned_documents(user_id):
    with db.cursor_scope() as cur:
        return db.get_documents_for_user(cur, user_id)


def list_shared_documents(user_id):
    with db.cursor_scope() as cur:
        return db.get_shared_documents_for_user(cur, user_id)
