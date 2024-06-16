# routes/auth/signup.py
from flask import Blueprint, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash
from models import User, Role
from forms import SignupForm
import logging

signup_bp = Blueprint("signup", __name__)


@signup_bp.route("/signup", methods=["GET", "POST"])
def signup_view():
    form = SignupForm()
    if form.validate_on_submit():
        user = User.query.filter(User.email.ilike(form.email.data)).first()
        if user:
            flash("User already exists", "error")
            logging.info("User already exists")
            return redirect(url_for("signup.signup_view"))

        role = Role.query.get(int(form.role.data))
        if not role:
            flash("Invalid role", "error")
            logging.info("Invalid role")
            return redirect(url_for("signup.signup_view"))

        signup_form_data = {
            "email": form.email.data,
            "password": generate_password_hash(form.password.data),
            "role_ids": [role.id],
        }
        if form.is_admin.data:  # Admin ONLY
            admin_role = Role.query.filter_by(name="Admin").first()
            if admin_role:
                signup_form_data["role_ids"].append(admin_role.id)
        session["signup_form_data"] = signup_form_data
        logging.info(f"signup_form_data: {signup_form_data}")
        return redirect(url_for("signup_user_details.signup_user_details_view"))
    return render_template("auth/signup.html", form=form)
