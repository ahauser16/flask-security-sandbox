# routes/auth/signup.py
from flask import Blueprint, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash
from models import User, Role
from forms import SignupForm
import logging
from .utils import (
    get_roles_from_db,
    verify_user_chosen_role_ids,
    get_user_chosen_role_ids,
)

signup_bp = Blueprint("signup", __name__)


@signup_bp.route("/signup", methods=["GET", "POST"])
def signup_view():
    form = SignupForm()
    logging.info("Form submitted for validation.")
    if form.validate_on_submit():
        logging.info("Form is valid.")
        user = User.query.filter(User.email.ilike(form.email.data)).first()
        if user:
            logging.info("User already exists.")
            flash("User already exists", "error")
            return render_template("auth/signup.html", form=form)

        roles_dict = get_roles_from_db()
        user_chosen_role_ids = get_user_chosen_role_ids(session)
        logging.info(f"User chosen role IDs: {user_chosen_role_ids}")

        try:
            matching_roles = verify_user_chosen_role_ids(
                roles_dict, user_chosen_role_ids
            )
            logging.info(f"Matching roles: {matching_roles}")
        except ValueError as e:
            logging.error(f"Error verifying roles: {e}")
            flash(str(e), "error")
            return render_template("auth/signup.html", form=form)

        signup_form_data = {
            "email": form.email.data,
            "password": generate_password_hash(form.password.data),
            "role_ids": list(matching_roles.keys()),
        }
        session["signup_form_data"] = signup_form_data
        logging.info(f"signup_form_data: {signup_form_data}")

        return redirect(url_for("signup_user_details.signup_user_details_view"))

    logging.info("Form is not valid.")
    return render_template("auth/signup.html", form=form)
