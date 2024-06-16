# routes/auth/signup_notary.py
from flask import Blueprint, render_template, redirect, url_for, flash, session
from models import Role
from forms import SignupNotaryForm
import logging
from api.notary_auth import match_notary_credentials


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
            flash("No matching data found in the API's database", "danger")
            logging.info("No matching data found in the API's database")
            return render_template("signup_notary.html", form=form)

        # Store the form data and API data in the session
        session["notary_cred_api_resp"] = notary_cred_api_resp
        logging.info(f"notary_cred_api_resp: {notary_cred_api_resp}")

        # Get the role_ids from the session
        signup_form_data = session.get("signup_form_data")
        role_ids = signup_form_data.get("role_ids") if signup_form_data else None
        logging.info(f"role_ids retrieved from session: {role_ids}")

        # Query the Role table to get the id of each role
        roles = Role.query.filter(
            Role.name.in_(["Admin", "Traditional Notary", "Electronic Notary"])
        ).all()
        role_ids_dict = {role.name: role.id for role in roles}
        logging.info(f"role_ids_dict: {role_ids_dict}")

        # Check the role_ids and redirect accordingly
        if has_roles(role_ids, role_ids_dict, ["Admin"]) and has_any_role(
            role_ids, role_ids_dict, ["Traditional Notary", "Electronic Notary"]
        ):
            return redirect(url_for("signup_admin.signup_admin_view"))
        elif has_any_role(
            role_ids, role_ids_dict, ["Traditional Notary", "Electronic Notary"]
        ):
            return redirect(url_for("confirm_registration.confirm_registration_view"))
        else:
            return redirect(url_for("throw_error.throw_error_view"))

    return render_template("auth/signup_notary.html", form=form)


def has_roles(role_ids, roles, role_names):
    return all(roles.get(role_name) in role_ids for role_name in role_names)


def has_any_role(role_ids, roles, role_names):
    return any(roles.get(role_name) in role_ids for role_name in role_names)
