# forms/auth/signup_forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, RadioField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from models import User

class SignupForm(FlaskForm):
    email = StringField("Email Address", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    role = RadioField(
        "Role",
        choices=[
            ("2", "Principal"),
            ("3", "Traditional Notary"),
            ("4", "Electronic Notary"),
        ],
        validators=[DataRequired()],
    )
    is_admin = BooleanField("Admin")
    submit = SubmitField("Submit")