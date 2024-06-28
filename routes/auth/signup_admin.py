# routes/auth/signup_admin.py
from flask import Blueprint, render_template, redirect, url_for, session
from forms import SignupAdminForm
import logging
from models import Role


signup_admin_bp = Blueprint("signup_admin", __name__)


@signup_admin_bp.route("/signup_admin", methods=["GET", "POST"])
def signup_admin_view():
    form = SignupAdminForm()
    # The form validation and special code handling is now within determine_redirect
    if form.validate_on_submit():
        return determine_redirect(form, session)

    return render_template("auth/signup_admin.html", form=form)


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


def determine_redirect(form, session):
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
