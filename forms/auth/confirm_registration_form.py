# forms/auth/confirm_registration_form.py
from flask_wtf import FlaskForm
from wtforms import SubmitField

class ConfirmRegistrationForm(FlaskForm):
    submit = SubmitField("Confirm Registration")