# forms/notary_log/signup_notary_form.py
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SubmitField
from wtforms.validators import DataRequired

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