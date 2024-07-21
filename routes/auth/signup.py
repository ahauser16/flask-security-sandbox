# routes/auth/signup.py
from flask import Blueprint, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash
from models import User, Role
from forms import SignupForm
import logging
from .utils import (
    get_roles_from_db,
)

signup_bp = Blueprint("signup", __name__)


# routes/auth/signup.py
@signup_bp.route("/signup", methods=["GET", "POST"])
def signup_view():
    form = SignupForm()
    roles_dict = get_roles_from_db()
    logging.info(f"roles_dict looks like: {roles_dict}")
    chosen_role_ids = []
    if form.validate_on_submit():
        logging.info(f"the 'form' object looks like: {form}")
        logging.info("Form submitted for validation.")
        
        user = User.query.filter(User.email.ilike(form.email.data)).first()
        if user:
            logging.info("User already exists.")
            flash("User already exists", "error")
            return render_template("auth/signup.html", form=form)

        if form.is_admin.data:
            admin_role = Role.query.filter_by(name="Admin").first()
            if admin_role:
                chosen_role_ids.append(admin_role.id)
                logging.info(f"chosen_role_ids should have the Admin id added: {chosen_role_ids}")

        if form.role.data:
            chosen_role = int(form.role.data)
            chosen_role_ids.append(chosen_role)
            if not chosen_role:
                logging.info(f"chosen_role_ids should have the chosen role id added: {chosen_role_ids}")

        signup_form_data = {
            "email": form.email.data,
            "password": generate_password_hash(form.password.data),
            "role_ids": chosen_role_ids,
        }
        session["signup_form_data"] = signup_form_data
        logging.info(f"signup_form_data looks like: {signup_form_data}")
        logging.info(f"chosen_role_ids looks like: {chosen_role_ids}")

        return redirect(url_for("signup_user_details.signup_user_details_view"))

    logging.info("Form is not valid.")
    return render_template("auth/signup.html", form=form)
