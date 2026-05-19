import pathlib

from .. import db
from .storage_service import compute_file_hash, get_user_storage_usage_bytes


def prepare_download(
    *,
    document_id: int,
    user_id: int,
    upload_folder: pathlib.Path,
    shared_only: bool,
    actor_id,
    denied_access_callback,
    denied_action: str,
    error_log_callback,
):
    with db.transaction_scope() as cur:
        row = db.get_document_by_id(cur, document_id)
        if not row:
            return {"ok": False, "status": 404, "message": "Document not found"}

        can_access = (
            db.can_access_shared_document(cur, document_id, user_id)
            if shared_only
            else db.can_access_document(cur, document_id, user_id)
        )
        if not can_access:
            denied_access_callback(denied_action, document_id, 404)
            return {"ok": False, "status": 404, "message": "Document not found"}

        stored_filename = row["storage_key"]
        download_filename = row["filename"]
        expected_hash = row["document_hash"]

        file_path = upload_folder / stored_filename
        if not file_path.exists() or not file_path.is_file():
            return {"ok": False, "status": 404, "message": "Document file not found"}

        try:
            calculated_hash = compute_file_hash(file_path)
        except OSError:
            db.write_audit_log(
                cur,
                actor_id=actor_id,
                action_type="document_integrity_check",
                result="hash_compute_error",
                target_document_id=document_id,
            )
            error_log_callback("hash_compute_error", document_id, user_id)
            return {"ok": False, "status": 500, "message": "Document temporarily unavailable"}

        if not expected_hash:
            db.update_document_hash(cur, document_id, calculated_hash)
            db.write_audit_log(
                cur,
                actor_id=actor_id,
                action_type="document_integrity_check",
                result="hash_backfilled",
                target_document_id=document_id,
            )
        elif expected_hash != calculated_hash:
            db.write_audit_log(
                cur,
                actor_id=actor_id,
                action_type="document_integrity_check",
                result="hash_mismatch",
                target_document_id=document_id,
            )
            error_log_callback("hash_mismatch", document_id, user_id)
            return {"ok": False, "status": 500, "message": "Document temporarily unavailable"}

    return {
        "ok": True,
        "stored_filename": stored_filename,
        "download_filename": download_filename,
    }


def check_upload_user_quota(*, user_id: int, upload_folder: pathlib.Path, file_size: int, max_files: int, storage_quota_bytes: int):
    with db.cursor_scope() as cur:
        user_file_count, user_storage_usage = get_user_storage_usage_bytes(cur, user_id, upload_folder)

    if max_files > 0 and user_file_count >= max_files:
        return {
            "ok": False,
            "reason": "max_files",
            "user_file_count": user_file_count,
            "user_storage_usage": user_storage_usage,
        }

    if storage_quota_bytes > 0 and user_storage_usage + file_size > storage_quota_bytes:
        return {
            "ok": False,
            "reason": "storage_quota",
            "user_file_count": user_file_count,
            "user_storage_usage": user_storage_usage,
        }

    return {
        "ok": True,
        "user_file_count": user_file_count,
        "user_storage_usage": user_storage_usage,
    }


def persist_uploaded_document(*, user_id: int, title: str, filename: str, storage_key: str, document_hash: str, metadata):
    with db.transaction_scope() as cur:
        db.insert_document(cur, user_id, title, filename, storage_key, document_hash, metadata)
