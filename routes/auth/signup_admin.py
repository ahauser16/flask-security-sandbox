# routes/auth/signup_admin.py
from flask import Blueprint, render_template, redirect, url_for, session, flash
from forms import SignupAdminForm
from flask import request  # Import at the top of your file
import logging
from models import Role
from .utils import (
    get_roles_from_db,
    get_user_chosen_role_ids,
    verify_user_chosen_role_ids,
)


signup_admin_bp = Blueprint("signup_admin", __name__)


@signup_admin_bp.route("/signup_admin", methods=["GET", "POST"])
def signup_admin_view():
    form = SignupAdminForm()
    # The form validation and special code handling is now within determine_redirect_signup_admin
    if form.validate_on_submit():
        return determine_redirect_signup_admin(form, session)
    elif request.method == "POST":
        flash(
            "incorrect passphrase", "error"
        )  # Flash message when form validation fails

    return render_template("auth/signup_admin.html", form=form)


def determine_redirect_signup_admin(form, session):
    try:
        roles_dict = get_roles_from_db()
        user_chosen_role_ids = get_user_chosen_role_ids(session)
        matching_roles = verify_user_chosen_role_ids(roles_dict, user_chosen_role_ids)

        if "Admin" in matching_roles.values():
            if form.validate_on_submit():
                session["special_code"] = form.special_code.data
                return redirect(
                    url_for("confirm_registration.confirm_registration_view")
                )

        logging.info("no matching roles found")
    except ValueError as e:
        logging.error(f"Error verifying roles: {e}")
