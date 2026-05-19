import os
import shutil
import threading
import time

import flask

from .common import BASE_DIR, get_client_ip, is_admin_session, log_denied_document_access, login_required
from .. import db
from ..security.input_controls import (
    is_safe_document_title,
    is_safe_upload,
    is_suspicious_search_query,
    normalize_search_query,
)
from ..security.pep import PolicyEnforcementPoint
from ..services import document_service
from ..services import document_file_service
from ..services.storage_service import (
    build_storage_key,
    extract_metadata,
    get_total_storage_usage_bytes,
    compute_file_hash,
)


documents_bp = flask.Blueprint("documents", __name__)

_upload_lock = threading.Lock()
_upload_rate_state: dict = {}


@documents_bp.route("/documents/<int:document_id>")
@login_required
def document_details(document_id):
    user_id = flask.session.get("user_id")
    current_role = flask.session.get("role")
    result, payload = document_service.get_document_details_view(
        document_id=document_id,
        user_id=user_id,
        is_admin=is_admin_session(),
    )

    if result == "forbidden":
        log_denied_document_access("details", document_id, 404)
        return "Document not found", 404

    if result == "not_found":
        return "Document not found", 404

    if current_role == "reviewer" and payload["document"]["owner_id"] == user_id:
        log_denied_document_access("details", document_id, 404)
        return "Document not found", 404

    return flask.render_template(
        "document_details.html",
        document=payload["document"],
        can_share=payload["can_share"],
        share_candidates=payload["share_candidates"],
        share_recipients=payload["share_recipients"],
    )


@documents_bp.route("/documents/<int:document_id>/share", methods=["POST"])
@login_required
def share_document(document_id):
    if flask.session.get("role") == "reviewer":
        return "Forbidden", 403

    if not PolicyEnforcementPoint.can_share_document(flask.session.get("role")):
        return "Forbidden", 403
    user_id = flask.session.get("user_id")
    shared_with_raw = flask.request.form.get("shared_with", "").strip()

    try:
        shared_with = int(shared_with_raw)
    except ValueError:
        return "Invalid target user", 400

    with db.transaction_scope() as cur:
        row = db.get_document_by_id(cur, document_id)
        if not row:
            return "Document not found", 404

        owner_id = row["owner_id"]
        if not PolicyEnforcementPoint.can_manage_document(
            actor_id=user_id,
            actor_role=flask.session.get("role"),
            owner_id=owner_id,
        ):
            db.write_audit_log(
                cur,
                actor_id=flask.session.get("user_id"),
                action_type="share_document",
                result="denied_not_owner_or_admin",
                target_user_id=shared_with,
                target_document_id=document_id,
            )
            log_denied_document_access("share", document_id, 404)
            return "Document not found", 404

        if shared_with == owner_id:
            return "Cannot share with owner", 400

        if not db.user_exists(cur, shared_with):
            return "Target user not found", 404

        already_shared = db.is_document_shared_with(cur, document_id, shared_with)
        if not already_shared:
            db.share_document_with_user(cur, document_id, shared_with)
            db.write_audit_log(
                cur,
                actor_id=flask.session.get("user_id"),
                action_type="share_document",
                result="success",
                target_user_id=shared_with,
                target_document_id=document_id,
            )
        else:
            db.write_audit_log(
                cur,
                actor_id=flask.session.get("user_id"),
                action_type="share_document",
                result="noop_already_shared",
                target_user_id=shared_with,
                target_document_id=document_id,
            )

    return flask.redirect(flask.url_for("documents.document_details", document_id=document_id))


@documents_bp.route("/documents/<int:document_id>/revoke", methods=["POST"])
@login_required
def revoke_document_share(document_id):
    if flask.session.get("role") == "reviewer":
        return "Forbidden", 403

    if not PolicyEnforcementPoint.can_share_document(flask.session.get("role")):
        return "Forbidden", 403
    user_id = flask.session.get("user_id")
    shared_with_raw = flask.request.form.get("shared_with", "").strip()

    try:
        shared_with = int(shared_with_raw)
    except ValueError:
        return "Invalid target user", 400

    with db.transaction_scope() as cur:
        row = db.get_document_by_id(cur, document_id)
        if not row:
            return "Document not found", 404

        owner_id = row["owner_id"]
        if not PolicyEnforcementPoint.can_manage_document(
            actor_id=user_id,
            actor_role=flask.session.get("role"),
            owner_id=owner_id,
        ):
            db.write_audit_log(
                cur,
                actor_id=flask.session.get("user_id"),
                action_type="revoke_document_share",
                result="denied_not_owner_or_admin",
                target_user_id=shared_with,
                target_document_id=document_id,
            )
            log_denied_document_access("revoke", document_id, 404)
            return "Document not found", 404

        revocation_done = db.revoke_document_share_for_user(cur, document_id, shared_with)
        db.write_audit_log(
            cur,
            action_type="revoke_document_share",
            actor_id=flask.session.get("user_id"),
            result="success" if revocation_done else "noop_not_shared",
            target_user_id=shared_with,
            target_document_id=document_id,
        )

    return flask.redirect(flask.url_for("documents.document_details", document_id=document_id))


@documents_bp.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    if flask.session.get("role") == "reviewer":
        log_denied_document_access("download", document_id, 404)
        return "Document not found", 404

    db.ensure_documents_hash_column(flask.current_app)
    user_id = flask.session.get("user_id")
    upload_folder = BASE_DIR / flask.current_app.config["UPLOAD_FOLDER"]

    def _log_download_error(kind: str, doc_id: int, actor_user_id: int):
        if kind == "hash_compute_error":
            flask.current_app.logger.exception(
                "Document hash computation failed doc_id=%s user_id=%s ip=%s",
                doc_id,
                actor_user_id,
                get_client_ip(),
            )
            return
        flask.current_app.logger.error(
            "Document integrity mismatch doc_id=%s user_id=%s ip=%s",
            doc_id,
            actor_user_id,
            get_client_ip(),
        )

    result = document_file_service.prepare_download(
        document_id=document_id,
        user_id=user_id,
        upload_folder=upload_folder,
        shared_only=False,
        actor_id=flask.session.get("user_id"),
        denied_access_callback=log_denied_document_access,
        denied_action="download",
        error_log_callback=_log_download_error,
    )

    if not result["ok"]:
        return result["message"], result["status"]

    return flask.send_from_directory(
        str(upload_folder),
        result["stored_filename"],
        as_attachment=True,
        download_name=result["download_filename"],
    )


@documents_bp.route("/documents")
@login_required
def documents_page():
    current_user_id = flask.session.get("user_id")
    current_role = flask.session.get("role")

    if current_role == "reviewer":
        return flask.redirect(flask.url_for("documents.shared_documents_page"))

    search_query = normalize_search_query(flask.request.args.get("search", ""))

    if search_query and is_suspicious_search_query(search_query):
        flask.current_app.logger.warning(
            "Blocked suspicious search payload user_id=%s ip=%s query=%r",
            current_user_id,
            get_client_ip(),
            search_query,
        )
        return "Invalid search query", 400

    documents = document_service.list_owned_documents(current_user_id)

    if search_query:
        search_lower = search_query.lower()
        documents = [
            d for d in documents if search_lower in d["title"].lower() or search_lower in d["filename"].lower()
        ]

    return flask.render_template(
        "documents.html",
        documents=documents,
        can_upload=PolicyEnforcementPoint.can_upload(current_role),
        requested_user_id=current_user_id,
        current_user_id=current_user_id,
        username=flask.session.get("username"),
        search_query=search_query,
    )


@documents_bp.route("/shared")
@login_required
def shared_documents_page():
    current_user_id = flask.session.get("user_id")
    search_query = normalize_search_query(flask.request.args.get("search", ""))

    if search_query and is_suspicious_search_query(search_query):
        flask.current_app.logger.warning(
            "Blocked suspicious shared-search payload user_id=%s ip=%s query=%r",
            current_user_id,
            get_client_ip(),
            search_query,
        )
        return "Invalid search query", 400

    documents = document_service.list_shared_documents(current_user_id)

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


@documents_bp.route("/shared/<int:document_id>/download")
@login_required
def download_shared_document(document_id):
    db.ensure_documents_hash_column(flask.current_app)
    user_id = flask.session.get("user_id")
    upload_folder = BASE_DIR / flask.current_app.config["UPLOAD_FOLDER"]

    def _log_shared_download_error(kind: str, doc_id: int, actor_user_id: int):
        if kind == "hash_compute_error":
            flask.current_app.logger.exception(
                "Shared document hash computation failed doc_id=%s user_id=%s ip=%s",
                doc_id,
                actor_user_id,
                get_client_ip(),
            )
            return
        flask.current_app.logger.error(
            "Shared document integrity mismatch doc_id=%s user_id=%s ip=%s",
            doc_id,
            actor_user_id,
            get_client_ip(),
        )

    result = document_file_service.prepare_download(
        document_id=document_id,
        user_id=user_id,
        upload_folder=upload_folder,
        shared_only=True,
        actor_id=flask.session.get("user_id"),
        denied_access_callback=log_denied_document_access,
        denied_action="shared_download",
        error_log_callback=_log_shared_download_error,
    )

    if not result["ok"]:
        return result["message"], result["status"]

    return flask.send_from_directory(
        str(upload_folder),
        result["stored_filename"],
        as_attachment=True,
        download_name=result["download_filename"],
    )


@documents_bp.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    db.ensure_documents_hash_column(flask.current_app)
    settings = flask.current_app.config["APP_SETTINGS"]
    user_id = flask.session.get("user_id")
    user_role = flask.session.get("role")

    if not PolicyEnforcementPoint.can_upload(user_role):
        return "Forbidden", 403

    title = flask.request.form.get("title", "Untitled").strip() or "Untitled"
    uploaded_file = flask.request.files.get("document")

    now = time.time()
    with _upload_lock:
        rate_entry = _upload_rate_state.setdefault(user_id, {"count": 0, "window_start": now})
        if now - rate_entry["window_start"] > settings.upload_rate_window:
            rate_entry["count"] = 0
            rate_entry["window_start"] = now
        rate_entry["count"] += 1
        upload_rate_exceeded = rate_entry["count"] > settings.upload_rate_limit

    if upload_rate_exceeded:
        flask.current_app.logger.warning(
            "Upload rate limit exceeded user_id=%s ip=%s count=%s window=%s",
            user_id,
            get_client_ip(),
            settings.upload_rate_limit,
            settings.upload_rate_window,
        )
        return "Too many upload requests. Please slow down.", 429

    if not is_safe_document_title(title):
        flask.flash("Invalid document title.", "error")
        return flask.redirect(flask.url_for("documents.documents_page"))

    if not uploaded_file or uploaded_file.filename == "":
        flask.flash("Please choose a file.", "error")
        return flask.redirect(flask.url_for("documents.documents_page"))

    is_valid_upload, sanitized_or_message = is_safe_upload(uploaded_file.filename)
    if not is_valid_upload:
        flask.flash(sanitized_or_message, "error")
        return flask.redirect(flask.url_for("documents.documents_page"))

    filename = sanitized_or_message
    storage_key = build_storage_key(filename)
    upload_folder = BASE_DIR / flask.current_app.config["UPLOAD_FOLDER"]
    upload_folder.mkdir(parents=True, exist_ok=True)
    os.chmod(upload_folder, 0o700)

    current_storage_usage = get_total_storage_usage_bytes(upload_folder)

    uploaded_file.stream.seek(0, os.SEEK_END)
    file_size = uploaded_file.stream.tell()
    uploaded_file.stream.seek(0)

    if file_size > flask.current_app.config["MAX_UPLOAD_BYTES"]:
        flask.flash("File too large.", "error")
        return flask.redirect(flask.url_for("documents.documents_page"))

    if (
        settings.global_storage_quota_bytes > 0
        and current_storage_usage + file_size > settings.global_storage_quota_bytes
    ):
        flask.current_app.logger.warning(
            "Global storage quota exceeded user_id=%s ip=%s usage=%s requested=%s quota=%s",
            user_id,
            get_client_ip(),
            current_storage_usage,
            file_size,
            settings.global_storage_quota_bytes,
        )
        return "Storage temporarily full. Please try again later.", 507

    disk_free_bytes = shutil.disk_usage(upload_folder).free
    if settings.min_free_disk_bytes > 0 and disk_free_bytes < settings.min_free_disk_bytes:
        flask.current_app.logger.warning(
            "Low disk space upload blocked user_id=%s ip=%s free=%s threshold=%s",
            user_id,
            get_client_ip(),
            disk_free_bytes,
            settings.min_free_disk_bytes,
        )
        return "Storage temporarily unavailable.", 507

    destination = upload_folder / storage_key

    quota_result = document_file_service.check_upload_user_quota(
        user_id=user_id,
        upload_folder=upload_folder,
        file_size=file_size,
        max_files=settings.user_max_files,
        storage_quota_bytes=settings.user_storage_quota_bytes,
    )
    if not quota_result["ok"]:
        if quota_result["reason"] == "max_files":
            flask.current_app.logger.warning(
                "User file quota exceeded user_id=%s ip=%s count=%s quota=%s",
                user_id,
                get_client_ip(),
                quota_result["user_file_count"],
                settings.user_max_files,
            )
            return "Upload quota exceeded.", 429
        flask.current_app.logger.warning(
            "User storage quota exceeded user_id=%s ip=%s usage=%s requested=%s quota=%s",
            user_id,
            get_client_ip(),
            quota_result["user_storage_usage"],
            file_size,
            settings.user_storage_quota_bytes,
        )
        return "Upload quota exceeded.", 429

    uploaded_file.save(destination)
    os.chmod(destination, 0o600)

    try:
        document_hash = compute_file_hash(destination)
    except OSError:
        try:
            if destination.exists():
                destination.unlink()
        except OSError:
            flask.current_app.logger.exception("Failed cleanup after hash computation error")
        flask.current_app.logger.exception(
            "Upload hash computation failed user_id=%s ip=%s filename=%s",
            user_id,
            get_client_ip(),
            filename,
        )
        return "Upload failed", 500

    metadata = extract_metadata(destination)

    document_file_service.persist_uploaded_document(
        user_id=user_id,
        title=title,
        filename=filename,
        storage_key=storage_key,
        document_hash=document_hash,
        metadata=metadata,
    )

    return flask.redirect(flask.url_for("documents.documents_page", uploaded=title))
