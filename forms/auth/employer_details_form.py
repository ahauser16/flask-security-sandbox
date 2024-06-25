# forms/auth/employer_details_form.py
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired
from ..utils import us_state_select_field


class EmployerDetailsForm(FlaskForm):
    company_name = StringField("Full Name", validators=[DataRequired()])
    street_address_line_one = StringField(
        "Street Address Line One", validators=[DataRequired()]
    )
    street_address_line_two = StringField("Street Address Line Two")
    city = StringField("City", validators=[DataRequired()])
    state = us_state_select_field()
    zip_code = StringField("Zip Code", validators=[DataRequired()])
    ein_number = StringField("EIN Number", validators=[DataRequired()])
    submit = SubmitField("Submit")
