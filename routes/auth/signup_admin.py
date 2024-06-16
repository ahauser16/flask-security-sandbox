# routes/auth/signup_admin.py
from flask import Blueprint, render_template, redirect, url_for, session
from forms import SignupAdminForm

signup_admin_bp = Blueprint("signup_admin", __name__)


@signup_admin_bp.route("/signup_admin", methods=["GET", "POST"])
def signup_admin_view():
    form = SignupAdminForm()
    if form.validate_on_submit():
        session["special_code"] = form.special_code.data
        return redirect(url_for("confirm_registration.confirm_registration_view"))

    return render_template("auth/signup_admin.html", form=form)
