# routes/auth/signup_employer_details.py
from flask import Blueprint, render_template, redirect, url_for, flash, session
from forms import EmployerDetailsForm
import logging
from models import Role, EmployerDetails, db, User


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

        return determine_redirect(session)

    return render_template("auth/signup_employer_details.html", form=form)


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


def handle_employer_submission(user_id, employer_data):
    # Extract the EIN number from the submitted data
    ein_number = employer_data['ein_number']
    
    # Check if an employer with this EIN already exists
    existing_employer = EmployerDetails.find_by_ein(ein_number)
    
    if existing_employer:
        # Employer exists, so link this user to the existing employer
        link_user_to_employer(user_id, existing_employer.id)
    else:
        # Employer does not exist, insert new employer details
        new_employer = insert_new_employer(employer_data)
        link_user_to_employer(user_id, new_employer.id)
        

# This function should update the user's `employer_id` field in the database to link them to the specified employer.
def link_user_to_employer(user_id, employer_id):
    user = User.query.get(user_id)
    if user:
        user.employer_id = employer_id
        db.session.commit()
        
        
# This function should create a new `EmployerDetails` instance with the provided data, save it to the database, and return the instance.
def insert_new_employer(employer_data):
    new_employer = EmployerDetails(
        name=employer_data['name'],
        street_address_line_one=employer_data['street_address_line_one'],
        street_address_line_two=employer_data['street_address_line_two'],
        city=employer_data['city'],
        state=employer_data['state'],
        zip_code=employer_data['zip_code'],
        ein_number=employer_data['ein_number']
    )
    db.session.add(new_employer)
    db.session.commit()
    return new_employer