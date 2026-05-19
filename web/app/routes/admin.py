import flask

from .common import is_admin_session, login_required
from ..services import admin_service


admin_bp = flask.Blueprint("admin", __name__)


@admin_bp.route("/admin/users")
@login_required
def admin_users_page():
    if not is_admin_session():
        return "Forbidden", 403

    users = admin_service.list_users()
    return flask.render_template("users.html", users=users)


@admin_bp.route("/admin/users/<int:user_id>/enable", methods=["POST"])
@login_required
def enable_user(user_id):
    if not is_admin_session():
        return "Forbidden", 403

    justification = flask.request.form.get("justification", "").strip()
    if not justification:
        return "Justification is required", 400

    result = admin_service.enable_user(
        user_id=user_id,
        actor_id=flask.session.get("user_id"),
        justification=justification,
    )
    if result == "not_found":
        return "User not found", 404

    return flask.redirect(flask.url_for("admin.admin_users_page"))


@admin_bp.route("/admin/users/<int:user_id>/disable", methods=["POST"])
@login_required
def disable_user(user_id):
    if not is_admin_session():
        return "Forbidden", 403

    justification = flask.request.form.get("justification", "").strip()
    if not justification:
        return "Justification is required", 400

    result = admin_service.disable_user(
        user_id=user_id,
        actor_id=flask.session.get("user_id"),
        current_username=flask.session.get("username"),
        justification=justification,
    )
    if result == "not_found":
        return "User not found", 404
    if result == "cannot_disable_current_admin":
        return "Cannot disable current admin user", 400
    if result == "cannot_disable_admin":
        return "Cannot disable admin account", 400

    return flask.redirect(flask.url_for("admin.admin_users_page"))
