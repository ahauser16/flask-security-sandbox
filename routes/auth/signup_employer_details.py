# routes/auth/signup_employer_details.py
from flask import Blueprint, render_template, redirect, url_for, flash, session
from forms import EmployerDetailsForm
import logging
from models import Role, EmployerDetails, db, User
from .utils import (
    get_roles_from_db,
    get_user_chosen_role_ids,
    verify_user_chosen_role_ids,
)


signup_employer_details_bp = Blueprint("signup_employer_details", __name__)


@signup_employer_details_bp.route("/signup_employer_details", methods=["GET", "POST"])
def signup_employer_details_view():
    form = EmployerDetailsForm()
    if form.validate_on_submit():
        if not verify_employer_duplicate_entry(form):
            return render_template("auth/signup_employer_details.html", form=form)

        # Create a dictionary from the form data and store it in the session
        signup_employer_details_form_data = {
            "name": form.company_name.data,
            "street_address_line_one": form.street_address_line_one.data,
            "street_address_line_two": form.street_address_line_two.data,
            "city": form.city.data,
            "state": form.state.data,
            "zip_code": form.zip_code.data,
            "ein_number": form.ein_number.data,
        }
        session["signup_employer_details_form_data"] = signup_employer_details_form_data
        logging.info(
            f"signup_employer_details_form_data: {signup_employer_details_form_data}"
        )

        return determine_redirect_signup_employer_details(session)

    return render_template("auth/signup_employer_details.html", form=form)


def determine_redirect_signup_employer_details(session):
    try:
        roles_dict = get_roles_from_db()
        user_chosen_role_ids = get_user_chosen_role_ids(session)
        matching_roles = verify_user_chosen_role_ids(roles_dict, user_chosen_role_ids)

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


def verify_employer_duplicate_entry(form):
    ein_number = form.ein_number.data
    existing_employer = EmployerDetails.find_by_ein(ein_number)
    if existing_employer:
        flash(
            "Employer record already registered. Contact your administrator.", "error"
        )
        return False
    return True
