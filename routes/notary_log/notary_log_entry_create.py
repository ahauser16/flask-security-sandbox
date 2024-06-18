# routes/notary_log/notary_log_entry_create.py
from flask import Blueprint, render_template, redirect, url_for
from flask_security import roles_accepted, current_user
from forms import NotarialActForm
from models import NotarialAct, db

notary_log_entry_create_bp = Blueprint("notary_log_entry_create", __name__)


@notary_log_entry_create_bp.route("/notary_log_entry_create", methods=["GET", "POST"])
@roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
def notary_log_entry_create():
    form = NotarialActForm()
    if form.validate_on_submit():
        form_data = form.data.copy()
        form_data.pop("submit", None)
        form_data.pop("csrf_token", None)
        form_data["user_id"] = current_user.id
        act = NotarialAct(**form_data)
        db.session.add(act)
        db.session.commit()
        return redirect(url_for("notary_log_view.notary_log_view"))
    return render_template(
        "notary_log/notary_log_entry_form.html",
        form=form,
    )
