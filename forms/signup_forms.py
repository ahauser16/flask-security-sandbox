# forms.py
from flask import session
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    RadioField,
    SubmitField,
    HiddenField,
    DateField,
    SelectField,
)
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
    commissioned_county = StringField(
        "Commissioned County", validators=[DataRequired()]
    )
    commission_start_date = DateField(
        "Commission Start Date", validators=[DataRequired()]
    )
    commission_expiration_date = DateField(
        "Commission Expiration Date", validators=[DataRequired()]
    )
    submit = SubmitField("Submit")


class UserDetailsForm(FlaskForm):
    email = HiddenField("Email")
    password = HiddenField("Password")
    role_id = HiddenField("Role ID")
    user_type = HiddenField("User Type", default=lambda: session.get("user_type"))
    full_name = StringField("Full Name", validators=[DataRequired()])
    street_address_line_one = StringField(
        "Street Address Line One", validators=[DataRequired()]
    )
    street_address_line_two = StringField("Street Address Line Two")
    city = StringField("City", validators=[DataRequired()])
    state = SelectField(
        "State",
        choices=[
            ("AL", "Alabama"),
            ("AK", "Alaska"),
            ("AZ", "Arizona"),
            ("AR", "Arkansas"),
            ("CA", "California"),
            ("CO", "Colorado"),
            ("CT", "Connecticut"),
            ("DE", "Delaware"),
            ("FL", "Florida"),
            ("GA", "Georgia"),
            ("HI", "Hawaii"),
            ("ID", "Idaho"),
            ("IL", "Illinois"),
            ("IN", "Indiana"),
            ("IA", "Iowa"),
            ("KS", "Kansas"),
            ("KY", "Kentucky"),
            ("LA", "Louisiana"),
            ("ME", "Maine"),
            ("MD", "Maryland"),
            ("MA", "Massachusetts"),
            ("MI", "Michigan"),
            ("MN", "Minnesota"),
            ("MS", "Mississippi"),
            ("MO", "Missouri"),
            ("MT", "Montana"),
            ("NE", "Nebraska"),
            ("NV", "Nevada"),
            ("NH", "New Hampshire"),
            ("NJ", "New Jersey"),
            ("NM", "New Mexico"),
            ("NY", "New York"),
            ("NC", "North Carolina"),
            ("ND", "North Dakota"),
            ("OH", "Ohio"),
            ("OK", "Oklahoma"),
            ("OR", "Oregon"),
            ("PA", "Pennsylvania"),
            ("RI", "Rhode Island"),
            ("SC", "South Carolina"),
            ("SD", "South Dakota"),
            ("TN", "Tennessee"),
            ("TX", "Texas"),
            ("UT", "Utah"),
            ("VT", "Vermont"),
            ("VA", "Virginia"),
            ("WA", "Washington"),
            ("WV", "West Virginia"),
            ("WI", "Wisconsin"),
            ("WY", "Wyoming"),
        ],
        validators=[DataRequired()],
    )
    zip_code = StringField("Zip Code", validators=[DataRequired()])
    submit = SubmitField("Submit")


class ConfirmRegistrationForm(FlaskForm):
    email = HiddenField("Email")
    password = HiddenField("Password")
    role_id = HiddenField("Role ID")
    full_name = HiddenField("Full Name")
    street_address_line_one = HiddenField("Street Address Line One")
    street_address_line_two = HiddenField("Street Address Line Two")
    city = HiddenField("City")
    state = HiddenField("State")
    zip_code = HiddenField("Zip Code")
    commission_holder_name = HiddenField("Commission Holder Name")
    commission_number_uid = HiddenField("Commission Number/UID")
    commissioned_county = HiddenField("Commissioned County")
    commission_start_date = HiddenField("Commission Start Date")
    commission_expiration_date = HiddenField("Commission Expiration Date")
    commission_type_traditional_or_electronic = HiddenField("Commission Type")
    submit = SubmitField("Confirm Registration")
