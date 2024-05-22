# forms.py
from flask import session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, RadioField, SubmitField, HiddenField, DateField
from wtforms.validators import DataRequired, Email


class SignupForm(FlaskForm):
    email = StringField("Email Address", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    options = RadioField(
        "Role",
        choices=[
            ("1", "Admin"),
            ("2", "Principal"),
            ("3", "Traditional Notary"),
            ("4", "Electronic Notary"),
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("Submit")


class SignupPrincipalForm(FlaskForm):
    email = HiddenField("Email")
    password = HiddenField("Password")
    user_type = HiddenField("User Type", default=lambda: session.get("user_type"))
    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    street_addr_line_one = StringField(
        "Street Address - Line One", validators=[DataRequired()]
    )
    street_addr_line_two = StringField(
        "Street Address - Line Two", validators=[DataRequired()]
    )
    street_addr_city = StringField("City", validators=[DataRequired()])
    street_addr_state = StringField("State", validators=[DataRequired()])
    street_addr_zip_code = StringField("Zip Code", validators=[DataRequired()])
    submit = SubmitField("Submit")


class SignupAdminForm(FlaskForm):
    email = HiddenField("Email")
    password = HiddenField("Password")
    user_type = HiddenField("User Type", default=lambda: session.get("user_type"))
    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    street_addr_line_one = StringField(
        "Street Address - Line One", validators=[DataRequired()]
    )
    street_addr_line_two = StringField(
        "Street Address - Line Two", validators=[DataRequired()]
    )
    street_addr_city = StringField("City", validators=[DataRequired()])
    street_addr_state = StringField("State", validators=[DataRequired()])
    street_addr_zip_code = StringField("Zip Code", validators=[DataRequired()])
    admin_code = StringField("Admin Code", validators=[DataRequired()])
    submit = SubmitField("Submit")

class SignupNotaryForm(FlaskForm):
    email = HiddenField("Email")
    password = HiddenField("Password")
    user_type = HiddenField("User Type", default=lambda: session.get("user_type"))
    full_name = StringField("Full Name", validators=[DataRequired()])
    commission_id = StringField("Commission ID", validators=[DataRequired()])
    commissioned_county = StringField("Commissioned County", validators=[DataRequired()])
    commission_start_date = DateField("Commission Start Date", validators=[DataRequired()])
    commission_expiration_date = DateField("Commission Expiration Date", validators=[DataRequired()])
    submit = SubmitField("Submit")
    
    
class ConfirmRegistrationForm(FlaskForm):
    confirm = SubmitField("Confirm Registration")