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
from forms.logbook_forms import NotarialActForm
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
from routes.auth import (
    signin_bp,
    signup_bp,
    signup_user_details_bp,
    signup_notary_bp,
    signup_admin_bp,
    confirm_registration_bp,
)


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

app.register_blueprint(signin_bp)
app.register_blueprint(signup_bp)
app.register_blueprint(signup_user_details_bp)
app.register_blueprint(signup_notary_bp)
app.register_blueprint(signup_admin_bp)
app.register_blueprint(confirm_registration_bp)

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/notarylogbook")
@roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
def notarylogbook():
    return render_template("notarylogbook/mynotarylogbook.html")


@app.route("/notary_log_entry", methods=["GET", "POST"])
@roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
def notary_log_entry():
    form = NotarialActForm()
    if form.validate_on_submit():
        form_data = form.data.copy()
        form_data.pop("submit", None)
        form_data.pop("csrf_token", None)
        form_data["user_id"] = current_user.id  # Set the user_id to current_user's id
        act = NotarialAct(**form_data)
        db.session.add(act)
        db.session.commit()
        return redirect(url_for("notarylogbook"))
    return render_template(
        "notarylogbook/notary_log_entry_form.html",
        form=form,
        action=url_for("notary_log_entry"),
    )


@app.route("/notary_log_entry/<int:id>", methods=["GET", "POST", "DELETE"])
@roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
def handle_notarial_act(id):
    act = NotarialAct.query.get(id)
    if (
        act.user_id != current_user.id
    ):  # Check if the current user is the owner of the act
        abort(403)  # If not, return a 403 Forbidden status code
    form = NotarialActForm(obj=act)
    if request.method == "POST":
        if form.validate_on_submit():
            form.populate_obj(act)
            db.session.commit()
            return redirect(url_for("notarylogbook"))
    elif request.method == "DELETE":
        db.session.delete(act)
        db.session.commit()
    elif request.method == "GET":
        return render_template(
            "notary_log_entry_form.html",
            form=form,
            action=url_for("handle_notarial_act", id=id),
        )
    return jsonify(success=False)


@app.template_filter("dateformat")
def dateformat(value, timezone):
    user_tz = pytz.timezone(timezone)
    return value.astimezone(user_tz).strftime("%Y-%m-%d")


@app.template_filter("timeformat")
def timeformat(value, timezone):
    user_tz = pytz.timezone(timezone)
    return value.astimezone(user_tz).strftime("%H:%M")


############################# notary logbook related routes above


############################ notary logbook data route code below
@app.route("/notarial_act_list")
def notarial_act_list():
    # Get the current user's ID
    current_user_id = current_user.id

    # Filter the NotarialAct records by the current user's ID
    query = NotarialAct.query.filter_by(user_id=current_user_id)

    # search filter
    search = request.args.get("search")
    logging.info(f"Received search parameter: {search}")
    if search:
        query = query.filter(
            db.or_(
                cast(NotarialAct.date_time, String).like(f"%{search}%"),
                NotarialAct.act_type.like(f"%{search}%"),
                NotarialAct.principal_name.like(f"%{search}%"),
                NotarialAct.principal_addressLine1.like(f"%{search}%"),
                NotarialAct.principal_addressLine2.like(f"%{search}%"),
                NotarialAct.principal_city.like(f"%{search}%"),
                NotarialAct.principal_state.like(f"%{search}%"),
                NotarialAct.principal_zipCode.like(f"%{search}%"),
                cast(NotarialAct.service_number, String).like(f"%{search}%"),
                NotarialAct.service_type.like(f"%{search}%"),
                NotarialAct.principal_credential_type.like(f"%{search}%"),
                NotarialAct.communication_tech.like(f"%{search}%"),
                NotarialAct.certification_authority.like(f"%{search}%"),
                NotarialAct.verification_provider.like(f"%{search}%"),
            )
        )
    total = query.count()
    logging.info(f"Total records before sorting and pagination: {total}")

    # sorting
    sort = request.args.get("sort")
    logging.info(f"Received sort parameters: {sort}")
    if sort:
        order = []
        for s in sort.split(","):
            direction = s[0]
            name = s[1:]
            logging.info(
                f"Processing sort parameter: {s}, direction: {direction}, name: {name}"
            )
            if name not in [
                "date_time",
                "act_type",
                "principal_name",
                "principal_addressLine1",
                "principal_addressLine2",
                "principal_city",
                "principal_state",
                "principal_zipCode",
                "service_number",
                "service_type",
                "principal_credential_type",
                "communication_tech",
                "certification_authority",
                "verification_provider",
            ]:
                return {"error": "Invalid column name for sorting: " + name}, 400
            col = getattr(NotarialAct, name)
            if direction == "-":
                col = col.desc()
            order.append(col)
        logging.info(f"Generated order: {order}")
        if order:
            query = query.order_by(*order)

    # pagination
    start = request.args.get("start", type=int, default=-1)
    length = request.args.get("length", type=int, default=-1)
    logging.info(f"Received pagination parameters: start={start}, length={length}")
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    data = [act.to_dict() for act in query]
    logging.info(f"Returning {len(data)} records")
    return {
        "data": data,
        "total": total,
    }


############################ notary logbook data route code above


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


##################################################


@app.route("/mydocuments", methods=["GET"])
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def mydocuments():
    # Query the documents from the database
    documents = PDFDocument.query.filter_by(user_id=current_user.id).all()
    delete_document_form = DeleteDocumentForm()
    return render_template(
        "documents/mydocuments.html",
        documents=documents,
        delete_document_form=delete_document_form,
    )


@app.route("/upload_document", methods=["GET", "POST"])
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def upload_document():
    form = UploadDocumentForm()
    if form.validate_on_submit():
        f = form.document.data
        filename = secure_filename(f.filename)
        file_data = f.read()  # Read the file data

        # Save the file to the file system
        file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        f.save(file_path)

        # Create a new PDFDocument object
        document = PDFDocument(
            filename=filename,
            filepath=file_path,  # Save the file path to the new column
            user_id=current_user.id,
            size=len(file_data),  # Update the size to the length of the file data
            content_type=f.content_type,
            notes=form.notes.data,  # Save the notes to the new column
        )

        # Get the document role
        document_role_name = form.document_role.data
        document_role = DocumentRole.query.filter_by(name=document_role_name).first()

        # Add the document role to the document
        document.document_roles.append(document_role)

        # Add the document to the session and commit
        db.session.add(document)
        db.session.commit()

        return redirect(url_for("mydocuments"))

    return render_template("documents/upload_document.html", form=form)


@app.route("/download_document/<int:document_id>")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def download_document(document_id):
    # Query the document from the database
    document = PDFDocument.query.get(document_id)
    if document is None:
        abort(404)  # Not found

    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], document.filename)
    print(f"File path: {file_path}")  # Print the file path

    if not os.path.isfile(file_path):
        print(
            f"File does not exist: {file_path}"
        )  # Print a message if the file does not exist

    # Send the file to the client
    return send_from_directory(current_app.config["UPLOAD_FOLDER"], document.filename)


@app.route("/delete_document/<int:document_id>", methods=["POST"])
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def delete_document(document_id):
    # Query the document from the database
    document = PDFDocument.query.get(document_id)
    if document is None:
        abort(404)  # Not found

    # Delete the file from the file system
    os.remove(document.filepath)

    # Delete the document from the database
    db.session.delete(document)
    db.session.commit()

    return redirect(url_for("mydocuments"))


@app.route("/view_document/<int:document_id>")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def view_document(document_id):
    # Query the document from the database
    document = PDFDocument.query.get(document_id)
    if document is None:
        abort(404)  # Not found

    # Render the view_document.html template
    return render_template("documents/view_document.html", document=document)


###############################


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
