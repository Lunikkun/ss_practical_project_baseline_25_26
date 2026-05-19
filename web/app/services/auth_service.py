from .. import db


def get_login_user(username):
    with db.cursor_scope() as cur:
        return db.get_user_by_username(cur, username)


def get_user_by_id(user_id):
    with db.cursor_scope() as cur:
        return db.get_user_by_id(cur, user_id)
