# routes/auth/signup_notary.py
from flask import Blueprint, render_template, redirect, url_for, flash, session
from models import Role
from forms import SignupNotaryForm
import logging
from api.notary_auth import match_notary_credentials
from .utils import (
    get_roles_from_db,
    get_user_chosen_role_ids,
    verify_user_chosen_role_ids,
)


signup_notary_bp = Blueprint("signup_notary", __name__)


@signup_notary_bp.route("/signup_notary", methods=["GET", "POST"])
def signup_notary_view():
    form = SignupNotaryForm()

    if form.validate_on_submit():
        notary_form_data = {
            "full_name": form.full_name.data,
            "commission_id": form.commission_id.data,
            "commissioned_county": form.commissioned_county.data,
            "commission_start_date": form.commission_start_date.data.strftime(
                "%Y-%m-%d"
            ),
            "commission_expiration_date": form.commission_expiration_date.data.strftime(
                "%Y-%m-%d"
            ),
        }
        logging.info(f"notary_form_data: {notary_form_data}")
        notary_cred_api_resp = match_notary_credentials(notary_form_data)
        if notary_cred_api_resp is None:
            flash("No matching data found in the API's database", "error")
            logging.info("No matching data found in the API's database")
            return render_template("auth/signup_notary.html", form=form)

        # Store the form data and API data in the session
        session["notary_cred_api_resp"] = notary_cred_api_resp
        logging.info(f"notary_cred_api_resp: {notary_cred_api_resp}")

        return determine_redirect_signup_notary(session)

    return render_template("auth/signup_notary.html", form=form)


def determine_redirect_signup_notary(session):
    try:
        roles_dict = get_roles_from_db()
        user_chosen_role_ids = get_user_chosen_role_ids(session)
        matching_roles = verify_user_chosen_role_ids(roles_dict, user_chosen_role_ids)

        if "Admin" in matching_roles.values():
            return redirect(url_for("signup_admin.signup_admin_view"))

        if "Principal" in matching_roles.values():
            return redirect(url_for("confirm_registration.confirm_registration_view"))

        logging.info("no matching roles found")
        # Add a default redirect or render_template here if no roles match
        return redirect(url_for("signup_notary.signup_notary_view"))
    except ValueError as e:
        logging.error(f"Error verifying roles: {e}")
        # Consider adding a redirect or render_template here to handle the error
        return redirect(url_for("throw_error.throw_error_view"))
