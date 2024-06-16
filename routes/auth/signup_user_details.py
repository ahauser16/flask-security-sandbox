# routes/auth/signup_user_details.py
from flask import Blueprint, render_template, redirect, url_for, flash, session
from models import Role
from forms import UserDetailsForm
import logging

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
        logging.info(f"signup_user_details_form_data: {signup_user_details_form_data}")

        # Get the role_ids from the session
        signup_form_data = session.get("signup_form_data")
        role_ids = signup_form_data.get("role_ids") if signup_form_data else None
        logging.info(f"role_ids retrieved from session: {role_ids}")

        # Query the Role table once and store the results in a dictionary
        roles = {role.name: role.id for role in Role.query.all()}
        logging.info(
            f"role_ids retrieved from the Role table and store them in a dicitonary as: {roles}"
        )

        # Check the role_ids and redirect accordingly
        if has_roles(role_ids, roles, ["Admin", "Principal"]):
            return redirect(url_for("signup_admin.signup_admin_view"))
        elif has_roles(role_ids, roles, ["Admin"]) and has_any_role(
            role_ids, roles, ["Traditional Notary", "Electronic Notary"]
        ):
            return redirect(url_for("signup_notary.signup_notary_view"))
        elif has_roles(role_ids, roles, ["Principal"]) and len(role_ids) == 1:
            return redirect(url_for("confirm_registration.confirm_registration_view"))
        elif (
            has_any_role(role_ids, roles, ["Traditional Notary", "Electronic Notary"])
            and len(role_ids) == 1
        ):
            return redirect(url_for("signup_notary.signup_notary_view"))
        else:
            return redirect(url_for("throw_error"))

    return render_template("auth/signup_user_details.html", form=form)


def has_roles(role_ids, roles, role_names):
    return all(roles.get(role_name) in role_ids for role_name in role_names)


def has_any_role(role_ids, roles, role_names):
    return any(roles.get(role_name) in role_ids for role_name in role_names)
