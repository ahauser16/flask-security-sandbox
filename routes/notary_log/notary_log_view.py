# routes/notary_log/notary_log_view.py
from flask import Blueprint, render_template
from flask_security import roles_accepted

notary_log_view_bp = Blueprint('notary_log_view', __name__)

@notary_log_view_bp.route("/notarylog")
@roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
def notary_log_view():
    return render_template("notary_log/my_notary_log.html")

