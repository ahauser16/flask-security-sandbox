# routes/notary_log/notary_log_entry_delete.py
from flask import Blueprint, redirect, url_for
from flask_security import roles_accepted
from models import NotarialAct, db

notary_log_entry_delete_bp = Blueprint("notary_log_entry_delete", __name__)


@notary_log_entry_delete_bp.route("/notary_log_entry_delete/<int:id>", methods=["POST"])
@roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
def notary_log_entry_delete(id):
    act = NotarialAct.query.get_or_404(id)
    db.session.delete(act)
    db.session.commit()
    return redirect(url_for("notary_log_view.notary_log_view"))
