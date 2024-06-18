# app.py
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    jsonify,
    session,
    abort,
    flash,
    current_app,
    send_file,
    send_from_directory,
    flash,
    get_flashed_messages,
)
from flask_sqlalchemy import SQLAlchemy
from flask_security import (
    UserMixin,
    RoleMixin,
    Security,
    SQLAlchemySessionUserDatastore,
    utils,
    roles_accepted,
)
from flask_login import LoginManager, login_manager, login_user, current_user
from flask_migrate import Migrate
from sqlalchemy import or_, cast, String
from google.cloud import storage
import requests
import logging
import pytz
from datetime import datetime
import urllib.parse
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
import os

from forms.signup_forms import (
    SignupForm,
    SignupAdminForm,
    SignupNotaryForm,
    ConfirmRegistrationForm,
    UserDetailsForm,
    SigninForm,
)
from forms.notary_log_forms import NotarialActForm
from forms.document_forms import UploadDocumentForm, DeleteDocumentForm

# below is the import statement from the models package after moving the model classes to their own folder
from models.database import (
    db,
    roles_users,
    document_role_documents,
    document_role_users,
)
from models import (
    User,
    Role,
    DocumentRole,
    UserDetails,
    EmployerDetails,
    PDFDocument,
    NotaryCredentials,
    NotarialAct,
)
from routes import all_blueprints


from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

migrate = Migrate(app, db)  # Initialize Migrate after db

app.app_context().push()

# Create a logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)  # Set the logging level to INFO

# Create a console handler
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)  # Set the handler level to INFO

# Add the handler to the logger
logger.addHandler(handler)

# retrieves the value of the UPLOAD_FOLDER configuration variable
upload_folder = app.config["UPLOAD_FOLDER"]


@app.before_first_request
def create_tables():
    db.create_all()

    # Check if roles already exist in the database
    if not Role.query.first():
        roles = [
            Role(id=1, name="Admin"),
            Role(id=2, name="Principal"),
            Role(id=3, name="Traditional Notary"),
            Role(id=4, name="Electronic Notary"),
        ]

        for role in roles:
            db.session.add(role)

        db.session.commit()
        print("Roles created successfully!")

    # Check if document roles already exist in the database
    if not DocumentRole.query.first():
        document_roles = [
            DocumentRole(id=1, name="Admin"),
            DocumentRole(id=2, name="Principal"),
            DocumentRole(id=3, name="Traditional Notary"),
            DocumentRole(id=4, name="Electronic Notary"),
        ]

        for document_role in document_roles:
            db.session.add(document_role)

        db.session.commit()
        print("Document roles created successfully!")


# below is the import statement from the models package after moving the model classes to their own folder
# Now that User and Role are defined, we can create the user_datastore and security
user_datastore = SQLAlchemySessionUserDatastore(db.session, User, Role)
security = Security(app, user_datastore)

# Attach the user_datastore to the app
app.user_datastore = user_datastore

for bp in all_blueprints:
    app.register_blueprint(bp)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/principals")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def principals():
    principals = ["johndoe@abc.com", "sumguy@abc.com", "princ5000@abc.com"]
    role_principals = db.session.query(roles_users).filter_by(role_id=2)
    for principal in role_principals:
        user = User.query.filter_by(id=principal.user_id).first()
        principals.append(user.email)
    return render_template("admin/principals.html", principals=principals)


@app.route("/trad_notaries")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def trad_notaries():
    trad_notaries = ["oldmannotary@aol.com", "papyrus@friendster.com"]
    role_trad_notaries = db.session.query(roles_users).filter_by(role_id=3)
    for trad_notary in role_trad_notaries:
        user = User.query.filter_by(id=trad_notary.user_id).first()
        trad_notaries.append(user.email)
    return render_template(
        "admin/traditionalnotaries.html", trad_notaries=trad_notaries
    )


@app.route("/e_notaries")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def e_notaries():
    e_notaries = ["amazo@gmail.com", "thefuture@yahoo.com"]
    role_e_notaries = db.session.query(roles_users).filter_by(role_id=4)
    for e_notary in role_e_notaries:
        user = User.query.filter_by(id=e_notary.user_id).first()
        e_notaries.append(user.email)
    return render_template("admin/electronicnotaries.html", e_notaries=e_notaries)


@app.route("/mydetails")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def mydetails():
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
    )


@app.route("/findnotary")
# @roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def findnotary():
    return render_template("findnotary/findnotary.html")


@app.route("/resourcecenter")
# @roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def resourcecenter():
    return render_template("resourcecenter/resourcecenter.html")


@app.route("/myesignature")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def myesignature():
    return render_template("esignatures/myesignature.html")


@app.route("/throw_error")
def throw_error():
    return render_template("errorhandling/throw_error.html")


if __name__ == "__main__":
    app.run(debug=True)
