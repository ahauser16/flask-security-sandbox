# forms/auth/user_signup_form.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, RadioField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from models import User, Role

class SignupForm(FlaskForm):
    email = StringField("Email Address", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    role = RadioField("Role", validators=[DataRequired()])
    is_admin = BooleanField("Admin")
    submit = SubmitField("Submit")
    
    def __init__(self, *args, **kwargs):
        super(SignupForm, self).__init__(*args, **kwargs)
        self.role.choices = [(str(role.id), role.name) for role in Role.query.filter(Role.name != "Admin").all()]
        