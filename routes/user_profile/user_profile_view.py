from flask import Blueprint, render_template
from flask_security import roles_accepted, current_user
from datetime import datetime
from models import User
from flask_login import current_user

user_profile_view_bp = Blueprint("user_profile_view", __name__)


@user_profile_view_bp.route("/mydetails")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def my_details():
    # Step 1: Get the current user's employer ID
    employer_id = current_user.employer_id

    # Step 2 & 3: Query for colleagues, excluding the current user
    colleagues = User.query.filter(
        User.employer_id == employer_id, User.id != current_user.id
    ).all()

    # Step 4: Pass colleagues to the template

    if current_user.notary_credentials:
        term_issue_date = datetime.strftime(
            current_user.notary_credentials.term_issue_date, "%m/%d/%Y"
        )
        term_expiration_date = datetime.strftime(
            current_user.notary_credentials.term_expiration_date, "%m/%d/%Y"
        )
    else:
        term_issue_date = None
        term_expiration_date = None

    return render_template(
        "user/mydetails.html",
        term_issue_date=term_issue_date,
        term_expiration_date=term_expiration_date,
        current_user=current_user,
        colleagues=colleagues,
    )
