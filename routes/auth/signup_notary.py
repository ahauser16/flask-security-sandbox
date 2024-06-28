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

        return determine_redirect(session)

    return render_template("auth/signup_notary.html", form=form)


def get_roles_from_db():
    # Query all roles from the Role table
    roles_query = Role.query.all()
    # Create a dictionary mapping id to name
    roles_dict = {role.id: role.name for role in roles_query}
    logging.info(f"roles_dict looks like: {roles_dict}")
    return roles_dict


def get_user_chosen_role_ids(session):
    # retrieve role_ids from the session
    user_chosen_role_ids = session.get("signup_form_data", {}).get("role_ids")
    # return the user's chosen role IDs
    logging.info(f"user_chosen_role_ids looks like: {user_chosen_role_ids}")
    return user_chosen_role_ids


def verify_user_chosen_role_ids(roles_dict, user_chosen_role_ids):
    """
    Verifies if the user chosen role IDs match any of the roles in roles_dict.

    :param roles_dict: A dictionary of roles from the database where key is role id and value is role name.
    :param user_chosen_role_ids: A list of role IDs chosen by the user.
    :return: A dictionary containing the id and name of the matching roles.
    :raises ValueError: If no matching roles are found.
    """
    matching_roles = {
        role_id: roles_dict[role_id]
        for role_id in user_chosen_role_ids
        if role_id in roles_dict
    }

    if not matching_roles:
        raise ValueError("unable to verify roles")

    logging.info(f"matching_roles looks like: {matching_roles}")
    return matching_roles


def determine_redirect(session):
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
