# routes/notary_log/notary_log_entry_read.py
from flask import Blueprint, render_template
from flask_security import roles_accepted
from models import NotarialAct

notary_log_entry_read_bp = Blueprint("notary_log_entry_read", __name__)


@notary_log_entry_read_bp.route("/notary_log_entry_read/<int:id>", methods=["GET"])
@roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
def notary_log_entry_read(id):
    act = NotarialAct.query.get_or_404(id)
    return render_template("notary_log/notary_log_entry_view.html", act=act)
