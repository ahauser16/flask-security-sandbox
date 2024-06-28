# routes/errors/throw_error_view.py
from flask import Blueprint, render_template

throw_error_view_bp = Blueprint('throw_error', __name__)

@throw_error_view_bp.route("/error")
def throw_error_view():
    return render_template("error_handling/throw_error.html")