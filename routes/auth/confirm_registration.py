#  routes/auth/confirm_registration.py
from flask import (
    render_template,
    redirect,
    url_for,
    session,
    flash,
    Blueprint,
    current_app,
)
from flask_security import SQLAlchemySessionUserDatastore
from flask_login import login_user
from datetime import datetime
import logging

from forms import ConfirmRegistrationForm
from models.database import db
from models import User, Role, UserDetails, NotaryCredentials, EmployerDetails
from datetime import datetime


confirm_registration_bp = Blueprint("confirm_registration", __name__)


@confirm_registration_bp.route("/confirm_registration", methods=["GET", "POST"])
def confirm_registration_view():
    user_datastore = current_app.user_datastore
    session_data = retrieve_appropriate_session_data(session)

    try:
        form = ConfirmRegistrationForm()

        if form.validate_on_submit():
            logging.info("Form validated")
            # Create user
            user = user_datastore.create_user(
                email=session_data["signup_form_data"]["email"],
                password=session_data["signup_form_data"]["password"],
            )
            logging.info(f"User created: {user}")

            # Add roles to user
            role_ids = get_user_chosen_role_ids(
                session
            )  # Assuming this function exists and retrieves role IDs from session
            for role_id in role_ids:
                role = Role.query.get(role_id)
                user_datastore.add_role_to_user(user, role)
            logging.info(f"Roles added to user: {role_ids}")

            # Commit to save user and roles
            db.session.commit()

            add_all_user_data_to_db(user, session_data)

            # Final commit to save all changes
            db.session.commit()
            logging.info("Changes committed to database")

            login_user(user)
            logging.info("User logged in and redirected to index page")
            return redirect(url_for("index"))

    except Exception as e:
        logging.error(f"An error occurred during registration: {e}")
        flash("An error occurred. Please try again.")
        return redirect(url_for("signup.signup_view"))

    # Extract role names for the template
    roles_dict = get_roles_from_db()
    session_role_names = [
        roles_dict[role_id]
        for role_id in get_user_chosen_role_ids(session)
        if role_id in roles_dict
    ]

    logging.info("Rendering confirm_registration.html template")
    return render_template(
        "auth/confirm_registration.html",
        form=form,
        role_names=session_role_names,
        signup_form_data=session_data.get("signup_form_data", {}),
        signup_user_details_form_data=session_data.get(
            "signup_user_details_form_data", {}
        ),
        signup_employer_details_form_data=session_data.get(
            "signup_employer_details_form_data", {}
        ),
        notary_cred_api_resp=session_data.get("notary_cred_api_resp", {}),
    )


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


def retrieve_appropriate_session_data(session):
    try:
        roles_dict = get_roles_from_db()
        user_chosen_role_ids = get_user_chosen_role_ids(session)
        matching_roles = verify_user_chosen_role_ids(roles_dict, user_chosen_role_ids)

        data = {
            "signup_form_data": session.get("signup_form_data", {}),
            "signup_user_details_form_data": session.get(
                "signup_user_details_form_data", {}
            ),
            "signup_employer_details_form_data": {},
            "notary_cred_api_resp": {},
        }

        if session.get("is_employer_associated", False):
            data["signup_employer_details_form_data"] = session.get(
                "signup_employer_details_form_data", {}
            )
        else:
            logging.info("no employer data submitted")

        if any(
            role_name in matching_roles.values()
            for role_name in ["Electronic Notary", "Traditional Notary"]
        ):
            data["notary_cred_api_resp"] = session.get("notary_cred_api_resp", {})
        else:
            logging.info("no Notary data submitted")

        if "Admin" in matching_roles.values():
            logging.info("Admin privileges requested")
        else:
            logging.info("no Admin privileges requested")

        return data

    except ValueError as e:
        logging.error(f"Error verifying roles: {e}")
        return {}


def add_all_user_data_to_db(user, session_data):
    # Check if signup_user_details_form_data exists and add to UserDetails
    if (
        "signup_user_details_form_data" in session_data
        and session_data["signup_user_details_form_data"]
    ):
        user_details_data = session_data["signup_user_details_form_data"]
        user_details = UserDetails(user_id=user.id, **user_details_data)
        db.session.add(user_details)
        logging.info("User details added to database")

    # Check if signup_employer_details_form_data exists and add to EmployerDetails
    if (
        "signup_employer_details_form_data" in session_data
        and session_data["signup_employer_details_form_data"]
    ):
        employer_details_data = session_data["signup_employer_details_form_data"]
        # Create EmployerDetails instance without user_id
        employer_details = EmployerDetails(**employer_details_data)
        db.session.add(employer_details)
        # Assign the created EmployerDetails instance to the user
        user.employer = employer_details
        logging.info("Employer details added to database")

    # Check if notary_cred_api_resp exists and add to NotaryCredentials
    if "notary_cred_api_resp" in session_data and session_data["notary_cred_api_resp"]:
        notary_cred_data = session_data["notary_cred_api_resp"]
        notary_credentials = NotaryCredentials(user_id=user.id, **notary_cred_data)
        db.session.add(notary_credentials)
        logging.info("Notary credentials added to database")
