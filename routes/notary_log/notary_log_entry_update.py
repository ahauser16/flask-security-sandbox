# routes/notary_log/notary_log_entry_update.py
from flask import Blueprint, render_template, redirect, url_for
from flask_security import roles_accepted
from forms import NotarialActForm
from models import NotarialAct, db

notary_log_entry_update_bp = Blueprint("notary_log_entry_update", __name__)


@notary_log_entry_update_bp.route(
    "/notary_log_entry_update/<int:id>", methods=["GET", "POST"]
)
@roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
def notary_log_entry_update(id):
    act = NotarialAct.query.get_or_404(id)
    form = NotarialActForm(obj=act)
    if form.validate_on_submit():
        form.populate_obj(act)
        db.session.commit()
        return redirect(url_for("notary_log_view.notary_log_view"))
    return render_template(
        "notary_log/notary_log_entry_form.html",
        form=form,
        # action=url_for("notary_log_entry_update.notary_log_entry_update"),
        id=id,
    )
