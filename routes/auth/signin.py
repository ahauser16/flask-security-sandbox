# routes/auth/signin.py
from flask import Blueprint, render_template, redirect, url_for
from flask_security import utils
from flask_login import login_user
from models import User
from forms import SigninForm

signin_bp = Blueprint("signin", __name__)


@signin_bp.route("/signin", methods=["GET", "POST"])
def signin_view():
    form = SigninForm()
    msg = ""
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if utils.verify_and_update_password(form.password.data, user):
                login_user(user)
                return redirect(url_for("index"))
            else:
                msg = "Wrong password"
        else:
            msg = "User doesn't exist"
    return render_template("auth/signin.html", form=form, msg=msg)
