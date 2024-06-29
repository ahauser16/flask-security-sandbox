# forms/admin/signup_admin_form.py
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, ValidationError


class SignupAdminForm(FlaskForm):
    special_code = StringField("Special Code", validators=[DataRequired()])
    submit = SubmitField("Submit")
