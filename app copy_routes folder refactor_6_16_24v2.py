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
from routes.auth.signin import signin_bp


from api.notary_auth import match_notary_credentials

from config import Config  # Import the Config class

app = Flask(__name__)
app.config.from_object(Config)  # Use the Config class for configuration

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

app.register_blueprint(signin_bp)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = User.query.filter(User.email.ilike(form.email.data)).first()
        if user:
            flash("User already exists", "error")
            logging.info("User already exists")
            return redirect(url_for("signup"))

        role = Role.query.get(int(form.role.data))
        if not role:
            flash("Invalid role", "error")
            logging.info("Invalid role")
            return redirect(url_for("signup"))

        signup_form_data = {
            "email": form.email.data,
            "password": generate_password_hash(form.password.data),
            "role_ids": [role.id],
        }
        if form.is_admin.data:  # Admin ONLY
            admin_role = Role.query.filter_by(name="Admin").first()
            if admin_role:
                signup_form_data["role_ids"].append(admin_role.id)
        session["signup_form_data"] = signup_form_data
        logging.info(f"signup_form_data: {signup_form_data}")
        return redirect(url_for("signup_user_details"))
    return render_template("auth/signup.html", form=form)


@app.route("/signup_user_details", methods=["GET", "POST"])
def signup_user_details():
    form = UserDetailsForm()
    if form.validate_on_submit():
        # Create a dictionary from the form data and store it in the session
        # user_details = {
        signup_user_details_form_data = {
            "full_name": form.full_name.data,
            "street_address_line_one": form.street_address_line_one.data,
            "street_address_line_two": form.street_address_line_two.data,
            "city": form.city.data,
            "state": form.state.data,
            "zip_code": form.zip_code.data,
            "timezone": form.timezone.data,
        }
        session["signup_user_details_form_data"] = signup_user_details_form_data
        logging.info(f"signup_user_details_form_data: {signup_user_details_form_data}")

        # Get the role_ids from the session
        signup_form_data = session.get("signup_form_data")
        role_ids = signup_form_data.get("role_ids") if signup_form_data else None
        logging.info(f"role_ids retrieved from session: {role_ids}")

        # Query the Role table once and store the results in a dictionary
        roles = {role.name: role.id for role in Role.query.all()}
        logging.info(
            f"role_ids retrieved from the Role table and store them in a dicitonary as: {roles}"
        )

        # Check the role_ids and redirect accordingly
        if has_roles(role_ids, roles, ["Admin", "Principal"]):
            return redirect(url_for("signup_admin"))
        elif has_roles(role_ids, roles, ["Admin"]) and has_any_role(
            role_ids, roles, ["Traditional Notary", "Electronic Notary"]
        ):
            return redirect(url_for("signup_notary"))
        elif has_roles(role_ids, roles, ["Principal"]) and len(role_ids) == 1:
            return redirect(url_for("confirm_registration"))
        elif (
            has_any_role(role_ids, roles, ["Traditional Notary", "Electronic Notary"])
            and len(role_ids) == 1
        ):
            return redirect(url_for("signup_notary"))
        else:
            return redirect(url_for("throw_error"))

    return render_template("auth/signup_user_details.html", form=form)


def has_roles(role_ids, roles, role_names):
    return all(roles.get(role_name) in role_ids for role_name in role_names)


def has_any_role(role_ids, roles, role_names):
    return any(roles.get(role_name) in role_ids for role_name in role_names)


@app.route("/signup_notary", methods=["GET", "POST"])
def signup_notary():
    form = SignupNotaryForm()

    if form.validate_on_submit():
        notary_form_data = {
            "full_name": form.full_name.data,
            "commission_id": form.commission_id.data,
            "commissioned_county": form.commissioned_county.data,
            "commission_start_date": form.commission_start_date.data.strftime(
                "%Y-%m-%d"
            ),
            "commission_expiration_date": form.commission_expiration_date.data.strftime(
                "%Y-%m-%d"
            ),
        }
        logging.info(f"notary_form_data: {notary_form_data}")
        notary_cred_api_resp = match_notary_credentials(notary_form_data)
        if notary_cred_api_resp is None:
            flash("No matching data found in the API's database", "danger")
            logging.info("No matching data found in the API's database")
            return render_template("signup_notary.html", form=form)

        # Store the form data and API data in the session
        session["notary_cred_api_resp"] = notary_cred_api_resp
        logging.info(f"notary_cred_api_resp: {notary_cred_api_resp}")

        # Get the role_ids from the session
        signup_form_data = session.get("signup_form_data")
        role_ids = signup_form_data.get("role_ids") if signup_form_data else None
        logging.info(f"role_ids retrieved from session: {role_ids}")

        # Query the Role table to get the id of each role
        roles = Role.query.filter(
            Role.name.in_(["Admin", "Traditional Notary", "Electronic Notary"])
        ).all()
        role_ids_dict = {role.name: role.id for role in roles}
        logging.info(f"role_ids_dict: {role_ids_dict}")

        # Check the role_ids and redirect accordingly
        if has_roles(role_ids, role_ids_dict, ["Admin"]) and has_any_role(
            role_ids, role_ids_dict, ["Traditional Notary", "Electronic Notary"]
        ):
            return redirect(url_for("signup_admin"))
        elif has_any_role(
            role_ids, role_ids_dict, ["Traditional Notary", "Electronic Notary"]
        ):
            return redirect(url_for("confirm_registration"))
        else:
            return redirect(url_for("throw_error"))

    return render_template("auth/signup_notary.html", form=form)


@app.route("/signup_admin", methods=["GET", "POST"])
def signup_admin():
    form = SignupAdminForm()
    if form.validate_on_submit():
        session["special_code"] = form.special_code.data
        return redirect(url_for("confirm_registration"))

    return render_template("auth/signup_admin.html", form=form)


@app.route("/confirm_registration", methods=["GET", "POST"])
def confirm_registration():
    try:
        logging.info("Entering confirm_registration route")

        # Check if the required session data is available
        required_keys = ["signup_form_data", "signup_user_details_form_data"]
        if not all(key in session for key in required_keys):
            logging.warning("Required session data not available")
            flash(
                "Session data is not available. Please start the registration process again."
            )
            return redirect(url_for("signup"))

        form = ConfirmRegistrationForm()

        # Get the role_ids from the session
        role_ids = session["signup_form_data"].get("role_ids", [])
        logging.info(f"Role IDs from session: {role_ids}")

        # This block queries the database for all roles and creates a dictionary mapping role IDs to role names.
        roles = Role.query.all()
        role_ids_dict = {role.id: role.name for role in roles}

        # This block uses the dictionary to map the role IDs from the session data to their names, and logs the role names.
        session_role_names = [
            role_ids_dict[role_id] for role_id in role_ids if role_id in role_ids_dict
        ]
        logging.info(f"Role names from session: {session_role_names}")

        # This block retrieves various pieces of data from the session and logs the notary credentials API response.
        signup_form_data = session.get("signup_form_data", {})
        signup_user_details_form_data = session.get("signup_user_details_form_data", {})
        notary_cred_api_resp = session.get("notary_cred_api_resp", {})

        logging.info(
            f"before validation signup_form_data looks like this: {signup_form_data}"
        )
        logging.info(
            f"before validation signup_user_details_form_data looks like this: {signup_user_details_form_data}"
        )
        logging.info(
            f"before validation notary_cred_api_resp looks like this: {notary_cred_api_resp}"
        )

        # This block formats the issue and expiration dates of the notary credentials.
        if 3 in role_ids or 4 in role_ids:
            notary_cred_api_resp["term_issue_date"] = datetime.strftime(
                notary_cred_api_resp["term_issue_date"], "%m/%d/%Y"
            )
            notary_cred_api_resp["term_expiration_date"] = datetime.strftime(
                notary_cred_api_resp["term_expiration_date"], "%m/%d/%Y"
            )

        # This line checks if the form has been submitted and is valid, and logs that the form has been validated.
        if form.validate_on_submit():
            logging.info("Form validated")
            # If the form is valid, This block creates a new user with the email and password from the form data, and logs the created user.
            user = user_datastore.create_user(
                email=signup_form_data["email"],
                password=signup_form_data["password"],
            )
            logging.info(
                f"User created: {user}"
            )  # example of output to log is "User created: <User (pending 139704404004096)>"

            # These lines add the roles associated with the user to the user's record in the database.
            for role_id in role_ids:
                role = Role.query.get(role_id)
                user_datastore.add_role_to_user(user, role)
            logging.info(
                f"Roles added to user: {role_ids}"
            )  # example of output to log is "Roles added to user: [4, 1]"

            db.session.commit()

            # This block creates a new `UserDetails` record for the user and adds it to the database session, and logs the user details.
            user_details_data = signup_user_details_form_data
            user_details_data["user_id"] = user.id
            user_details = UserDetails(**user_details_data)
            logging.info(
                f"user_details_data looks like this: {user_details_data}"  # {'city': 'Brooklyn', 'full_name': 'ARTHUR John HAUSER', 'state': 'NY', 'street_address_line_one': '415 East 16th Street', 'street_address_line_two': 'Apartment A8', 'timezone': 'US/Eastern', 'zip_code': '11226', 'user_id': None}
            )

            db.session.add(user_details)
            logging.info(
                f"User details added to session: {user_details}"
            )  # example of output to log is "User details added to session: <UserDetails (pending 139704404006304)>"

            # This block checks if the user is a notary. If so, it creates a new NotaryCredentials record for the user and adds it to the database session, and logs that the notary credentials have been added.
            if (
                "Traditional Notary" in session_role_names
                or "Electronic Notary" in session_role_names
            ):
                notary_credentials_data = notary_cred_api_resp
                notary_credentials_data["user_id"] = user.id
                notary_credentials = NotaryCredentials(**notary_credentials_data)
                db.session.add(notary_credentials)
                logging.info(
                    "Notary credentials added to database session as {notary_credentials}"
                )

            # This line commits the changes to the database. This is when the new user, user details, and notary credentials (if applicable) are actually saved to the database.
            db.session.commit()
            logging.info("Changes committed to database")

            # This block logs the user in, logs that the user has been logged in and redirected, and redirects the user to the index page.
            login_user(user)
            logging.info("User logged in and redirected to index page")
            return redirect(url_for("index"))

    # This block catches any exceptions that occur during the registration process, logs the exception, flashes a message to the user, and redirects the user to the signup page.
    except Exception as e:
        logging.error(f"An error occurred during registration: {e}")
        flash("An error occurred. Please try again.")
        return redirect(url_for("signup"))

    # This block logs that the "confirm_registration.html" template is being rendered, and renders the template, passing the form and various pieces of data to the template. This allows the template to generate HTML that represents the form and includes the data.
    logging.info("Rendering confirm_registration.html template")
    return render_template(
        "auth/confirm_registration.html",
        form=form,
        role_names=session_role_names,
        signup_form_data=signup_form_data,
        signup_user_details_form_data=signup_user_details_form_data,
        notary_cred_api_resp=notary_cred_api_resp,
    )


# @app.route("/signin", methods=["GET", "POST"])
# def signin():
#     form = SigninForm()
#     msg = ""
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         if user:
#             if utils.verify_and_update_password(form.password.data, user):
#                 login_user(user)
#                 return redirect(url_for("index"))
#             else:
#                 msg = "Wrong password"
#         else:
#             msg = "User doesn't exist"
#     return render_template("auth/signin.html", form=form, msg=msg)


############################## notary logbook related routes below


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
