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
    SelectMultipleField,
    BooleanField,
)
from wtforms.validators import DataRequired, Email, ValidationError
from pytz import all_timezones


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


class UserDetailsForm(FlaskForm):
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
    timezone = SelectField("Timezone", choices=[(tz, tz) for tz in all_timezones])
    submit = SubmitField("Submit")


class SignupNotaryForm(FlaskForm):
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


class SignupAdminForm(FlaskForm):
    special_code = StringField("Special Code", validators=[DataRequired()])
    submit = SubmitField("Submit")

    def validate_special_code(form, field):
        if field.data != "swordfish":
            raise ValidationError("Invalid special code.")


class ConfirmRegistrationForm(FlaskForm):
    email = HiddenField()
    password = HiddenField()
    role = HiddenField()
    is_admin = HiddenField()
    submit = SubmitField("Confirm Registration")
