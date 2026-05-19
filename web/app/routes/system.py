import flask

from .. import db


system_bp = flask.Blueprint("system", __name__)


@system_bp.route("/health")
def health():
    try:
        with db.cursor_scope() as cur:
            db.health_check(cur)
        return {"status": "ok"}, 200
    except Exception:
        return {"status": "error"}, 500
