# forms/notary_log/signup_notary_form.py
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SubmitField
from wtforms.validators import DataRequired
from ..utils import ny_county_select_field


class SignupNotaryForm(FlaskForm):
    full_name = StringField("Full Name", validators=[DataRequired()])
    commission_id = StringField("Commission ID", validators=[DataRequired()])
    commissioned_county = ny_county_select_field()
    commission_start_date = DateField(
        "Commission Start Date", validators=[DataRequired()]
    )
    commission_expiration_date = DateField(
        "Commission Expiration Date", validators=[DataRequired()]
    )
    submit = SubmitField("Submit")
