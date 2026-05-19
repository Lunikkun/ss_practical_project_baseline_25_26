from .. import db


def list_users():
    with db.cursor_scope() as cur:
        return db.get_all_users(cur)


def enable_user(user_id, actor_id, justification):
    with db.transaction_scope() as cur:
        target = db.get_user_by_id(cur, user_id)
        if not target:
            return "not_found"

        db.set_user_disabled(cur, user_id, False)
        db.write_audit_log(
            cur,
            actor_id=actor_id,
            action_type="enable_user",
            result="success",
            target_user_id=user_id,
            justification=justification,
        )
    return "ok"


def disable_user(user_id, actor_id, current_username, justification):
    with db.transaction_scope() as cur:
        target = db.get_user_by_id(cur, user_id)
        if not target:
            return "not_found"

        target_username = target["username"]
        target_role = target["role"]

        if target_username == current_username:
            return "cannot_disable_current_admin"

        if target_role == "admin":
            return "cannot_disable_admin"

        db.set_user_disabled(cur, user_id, True)
        db.write_audit_log(
            cur,
            actor_id=actor_id,
            action_type="disable_user",
            result="success",
            target_user_id=user_id,
            justification=justification,
        )
    return "ok"
