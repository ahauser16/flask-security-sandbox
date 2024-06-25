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

    try:
        logging.info("Entering confirm_registration route")

        # Check if the required session data is available
        required_keys = [
            "signup_form_data",
            "signup_user_details_form_data",
            "signup_employer_details_form_data",
        ]
        if not all(key in session for key in required_keys):
            logging.warning("Required session data not available")
            flash(
                "Session data is not available. Please start the registration process again."
            )
            return redirect(url_for("signup.signup_view"))

        form = ConfirmRegistrationForm()

        role_ids = session["signup_form_data"].get("role_ids", [])
        logging.info(f"Role IDs from session: {role_ids}")

        roles = Role.query.all()
        role_ids_dict = {role.id: role.name for role in roles}

        session_role_names = [
            role_ids_dict[role_id] for role_id in role_ids if role_id in role_ids_dict
        ]
        logging.info(f"Role names from session: {session_role_names}")

        # Retrieve session data
        signup_form_data = session.get("signup_form_data", {})
        signup_user_details_form_data = session.get("signup_user_details_form_data", {})
        signup_employer_details_form_data = session.get(
            "signup_employer_details_form_data", {}
        )
        notary_cred_api_resp = session.get("notary_cred_api_resp", {})

        logging.info(
            f"before validation signup_form_data looks like this: {signup_form_data}"
        )
        logging.info(
            f"before validation signup_user_details_form_data looks like this: {signup_user_details_form_data}"
        )
        logging.info(
            f"before validation notary_cred_api_resp looks like this: {notary_cred_api_resp}"
        )
        logging.info(
            f"before validation signup_employer_details_form_data looks like this: {signup_employer_details_form_data}"
        )

        if 3 in role_ids or 4 in role_ids:
            # Convert string to datetime object using the correct format
            term_issue_date_obj = datetime.strptime(
                notary_cred_api_resp["term_issue_date"], "%m/%d/%Y"
            )
            term_expiration_date_obj = datetime.strptime(
                notary_cred_api_resp["term_expiration_date"], "%m/%d/%Y"
            )
            notary_cred_api_resp["term_issue_date"] = term_issue_date_obj.strftime(
                "%m/%d/%Y"
            )
            notary_cred_api_resp["term_expiration_date"] = (
                term_expiration_date_obj.strftime("%m/%d/%Y")
            )

        if form.validate_on_submit():
            logging.info("Form validated")
            # Create user
            user = user_datastore.create_user(
                email=signup_form_data["email"],
                password=signup_form_data["password"],
            )
            logging.info(f"User created: {user}")

            # Add roles to user
            for role_id in role_ids:
                role = Role.query.get(role_id)
                user_datastore.add_role_to_user(user, role)
            logging.info(f"Roles added to user: {role_ids}")

            # Commit to save user and roles
            db.session.commit()

            user_details_data = signup_user_details_form_data
            user_details_data["user_id"] = user.id
            user_details = UserDetails(**user_details_data)
            logging.info(f"user_details_data looks like this: {user_details_data}")

            db.session.add(user_details)
            logging.info(f"User details added to session: {user_details}")

            employer_details_data = signup_employer_details_form_data
            employer_details_data["user_id"] = user.id
            employer_details = EmployerDetails(**employer_details_data)
            logging.info(
                f"employer_details_data looks like this: {employer_details_data}"
            )

            db.session.add(employer_details)
            logging.info(f"Employer details added: {employer_details}")

            if (
                "Traditional Notary" in session_role_names
                or "Electronic Notary" in session_role_names
            ):
                notary_credentials_data = notary_cred_api_resp
                notary_credentials_data["user_id"] = user.id
                notary_credentials = NotaryCredentials(**notary_credentials_data)
                db.session.add(notary_credentials)
                logging.info(
                    "Notary credentials added to database session as {notary_credentials}"
                )

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

    logging.info("Rendering confirm_registration.html template")
    return render_template(
        "auth/confirm_registration.html",
        form=form,
        role_names=session_role_names,
        signup_form_data=signup_form_data,
        signup_user_details_form_data=signup_user_details_form_data,
        signup_employer_details_form_data=signup_employer_details_form_data,
        notary_cred_api_resp=notary_cred_api_resp,
    )
