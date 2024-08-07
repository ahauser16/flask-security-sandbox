# forms/auth/user_details_form.py
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired
from pytz import all_timezones
from ..utils import us_state_select_field


class UserDetailsForm(FlaskForm):
    full_name = StringField("Full Name", validators=[DataRequired()])
    street_address_line_one = StringField(
        "Street Address Line One", validators=[DataRequired()]
    )
    street_address_line_two = StringField("Street Address Line Two")
    city = StringField("City", validators=[DataRequired()])
    state = us_state_select_field()
    zip_code = StringField("Zip Code", validators=[DataRequired()])
    timezone = SelectField("Timezone", choices=[(tz, tz) for tz in all_timezones])
    is_employer_associated = BooleanField(
        "Do you want to link your employer to your account?"
    )
    submit = SubmitField("Submit")
