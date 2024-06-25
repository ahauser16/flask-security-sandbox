# routes/auth/signup_employer_details.py
from flask import Blueprint, render_template, redirect, url_for, flash, session
from forms import EmployerDetailsForm
import logging
from models import Role


signup_employer_details_bp = Blueprint("signup_employer_details", __name__)


@signup_employer_details_bp.route("/signup_employer_details", methods=["GET", "POST"])
def signup_employer_details_view():
    form = EmployerDetailsForm()
    if form.validate_on_submit():
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

        return redirect_from_employer_details()

    return render_template("auth/signup_employer_details.html", form=form)


def has_roles(role_ids, roles, role_names):
    return all(roles.get(role_name) in role_ids for role_name in role_names)


def has_any_role(role_ids, roles, role_names):
    return any(roles.get(role_name) in role_ids for role_name in role_names)


def redirect_from_employer_details():
    role_ids = session.get("role_ids", [])
    roles = {
        role.id: role.name for role in Role.query.all()
    }  # Assuming Role model exists and is imported

    notary_roles = ["Traditional Notary", "Electronic Notary"]
    if has_any_role(role_ids, roles, notary_roles):
        return redirect(url_for("signup_notary.signup_notary_view"))
    elif has_roles(role_ids, roles, ["Admin"]):
        return redirect(url_for("signup_admin.signup_admin_view"))
    else:
        return redirect(url_for("confirm_registration.confirm_registration_view"))
