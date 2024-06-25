# routes/auth/__init__.py
from .signin import signin_bp
from .signup import signup_bp
from .signup_user_details import signup_user_details_bp
from .signup_notary import signup_notary_bp
from .signup_admin import signup_admin_bp
from .confirm_registration import confirm_registration_bp
from .signup_employer_details import signup_employer_details_bp

auth_blueprints = [
    signin_bp,
    signup_bp,
    signup_user_details_bp,
    signup_notary_bp,
    signup_admin_bp,
    confirm_registration_bp,
    signup_employer_details_bp
]
