# routes/auth/signup_user_details.py
from flask import Blueprint, render_template, redirect, url_for, flash, session
from models import Role
from forms import UserDetailsForm
import logging
from .utils import (
    get_roles_from_db,
    get_user_chosen_role_ids,
    verify_user_chosen_role_ids,
)

signup_user_details_bp = Blueprint("signup_user_details", __name__)


@signup_user_details_bp.route("/signup_user_details", methods=["GET", "POST"])
def signup_user_details_view():
    form = UserDetailsForm()
    if form.validate_on_submit():
        # Create a dictionary from the form data and store it in the session
        signup_user_details_form_data = {
            "full_name": form.full_name.data,
            "street_address_line_one": form.street_address_line_one.data,
            "street_address_line_two": form.street_address_line_two.data,
            "city": form.city.data,
            "state": form.state.data,
            "zip_code": form.zip_code.data,
            "timezone": form.timezone.data,
        }

        session["signup_user_details_form_data"] = signup_user_details_form_data

        # Store is_employer_associated separately in session if needed for logic but not in the database
        session["is_employer_associated"] = form.is_employer_associated.data
        logging.info(f"signup_user_details_form_data: {signup_user_details_form_data}")

        return determine_redirect_signup_user_details(form, session)

    return render_template("auth/signup_user_details.html", form=form)


def determine_redirect_signup_user_details(form, session):
    try:
        roles_dict = get_roles_from_db()
        user_chosen_role_ids = get_user_chosen_role_ids(session)
        matching_roles = verify_user_chosen_role_ids(roles_dict, user_chosen_role_ids)

        if form.is_employer_associated.data:
            return redirect(
                url_for("signup_employer_details.signup_employer_details_view")
            )

        notary_roles = ["Electronic Notary", "Traditional Notary"]
        if any(role_name in matching_roles.values() for role_name in notary_roles):
            return redirect(url_for("signup_notary.signup_notary_view"))

        if "Admin" in matching_roles.values():
            return redirect(url_for("signup_admin.signup_admin_view"))

        if "Principal" in matching_roles.values():
            return redirect(url_for("confirm_registration.confirm_registration_view"))

        logging.info("no matching roles found")
    except ValueError as e:
        logging.error(f"Error verifying roles: {e}")
