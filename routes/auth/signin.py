# routes/auth/signin.py
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_security import utils
from flask_login import login_user
from models import User
from forms import SigninForm

signin_bp = Blueprint("signin", __name__)

@signin_bp.route("/signin", methods=["GET", "POST"])
def signin_view():
    form = SigninForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if utils.verify_and_update_password(form.password.data, user):
                login_user(user)
                flash('You were successfully logged in', 'success')
                return redirect(url_for("index"))
            else:
                flash('Login failed, please try again', 'error')
        else:
            flash('Login failed, please try again', 'error')
    return render_template("auth/signin.html", form=form)