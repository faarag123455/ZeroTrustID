from flask import Blueprint, render_template

from app.models.db import get_db
from app.security.decorators import require_permission

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/logs")
@require_permission("logs:read")
def logs():
    rows = get_db().execute(
        "SELECT id, event_type, user_id, ip, details, created_at "
        "FROM security_logs ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("admin_logs.html", logs=rows)