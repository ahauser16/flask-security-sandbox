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
import os

from forms.signup_forms import (
    SignupForm,
    SignupAdminForm,
    SignupNotaryForm,
    ConfirmRegistrationForm,
    UserDetailsForm,
)
from forms.logbook_forms import NotarialActForm
from forms.document_forms import UploadDocumentForm

# from routes.routes import index
from api.notary_auth import match_notary_credentials

from config import Config  # Import the Config class


app = Flask(__name__)
app.config.from_object(Config)  # Use the Config class for configuration

db = SQLAlchemy()
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


# role_users must be defined before the User and Role classes
roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
)


# DocumentRole-User is an association table that links `User` and `DocumentRole``
document_role_users = db.Table(
    "document_role_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("document_role_id", db.Integer(), db.ForeignKey("document_role.id")),
)


class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String(255), nullable=False, server_default="")
    active = db.Column(db.Boolean())
    roles = db.relationship("Role", secondary=roles_users, backref="roled")
    notary_credentials = db.relationship(
        "NotaryCredentials", backref="user_notary_credentials", uselist=False
    )
    user_details = db.relationship("UserDetails", backref="user", uselist=False)
    employer_id = db.Column(
        db.Integer, db.ForeignKey("employer_details.id"), nullable=True
    )
    # The document_roles field is a relationship field that links a user or a document to its roles.
    document_roles = db.relationship(
        "DocumentRole", secondary=document_role_users, backref="users"
    )


class Role(db.Model, RoleMixin):
    __tablename__ = "role"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)


# Now that User and Role are defined, we can create the user_datastore and security
user_datastore = SQLAlchemySessionUserDatastore(db.session, User, Role)
security = Security(app, user_datastore)


# DocumentRole model represents the role a user takes when dealing with a specific document.
class DocumentRole(db.Model):
    __tablename__ = "document_role"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)


# DocumentRole-PDFDocument is an association table that links PDFDocument and DocumentRole
document_role_documents = db.Table(
    "document_role_documents",
    db.Column("pdf_document_id", db.Integer(), db.ForeignKey("pdf_document.id")),
    db.Column("document_role_id", db.Integer(), db.ForeignKey("document_role.id")),
)


class UserDetails(db.Model):
    __tablename__ = "user_details"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    timezone = db.Column(db.String(50), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    street_address_line_one = db.Column(db.String(255), nullable=False)
    street_address_line_two = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(2), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)


class EmployerDetails(db.Model):
    __tablename__ = "employer_details"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    street_address_line_one = db.Column(db.String(255), nullable=False)
    street_address_line_two = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(2), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    ein_number = db.Column(db.String(20), nullable=False, unique=True)
    users = db.relationship("User", backref="employer", lazy=True)


class PDFDocument(db.Model):
    __tablename__ = "pdf_document"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    file_url = db.Column(db.String(200), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(10), nullable=False, default="Unsigned")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref="pdf_documents")
    size = db.Column(db.Integer)  # Size of the file in bytes
    content_type = db.Column(db.String(100))  # MIME type of the file
    # The document_roles field is a relationship field that links a user or a document to its roles.
    document_roles = db.relationship(
        "DocumentRole", secondary=document_role_documents, backref="pdf_documents"
    )


class NotaryCredentials(db.Model):
    __tablename__ = "notary_credentials"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    commission_holder_name = db.Column(db.String(100))
    commission_number_uid = db.Column(db.String(100))
    commissioned_county = db.Column(db.String(100))
    commission_type_traditional_or_electronic = db.Column(db.String(100))
    term_issue_date = db.Column(db.DateTime)
    term_expiration_date = db.Column(db.DateTime)
    user = db.relationship("User", backref="notary_credentials_backref", uselist=False)


class NotarialAct(db.Model):
    __tablename__ = "notarial_act"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    date_time = db.Column(db.DateTime, default=datetime.utcnow)
    act_type = db.Column(db.String(100))
    principal_name = db.Column(db.String(100))
    principal_addressLine1 = db.Column(db.String(100))
    principal_addressLine2 = db.Column(db.String(100))
    principal_city = db.Column(db.String(100))
    principal_state = db.Column(db.String(2))
    principal_zipCode = db.Column(db.String(100))
    service_number = db.Column(db.Integer)
    service_type = db.Column(db.String(100))
    principal_credential_type = db.Column(db.String(100))
    communication_tech = db.Column(db.String(100), nullable=True)
    certification_authority = db.Column(db.String(100), nullable=True)
    verification_provider = db.Column(db.String(100), nullable=True)
    user = db.relationship("User", backref=db.backref("notarial_acts", lazy=True))

    def to_dict(self):
        if self.user and self.user.user_details and self.user.user_details.timezone:
            user_tz = pytz.timezone(self.user.user_details.timezone)
            local_date_time = (
                self.date_time.astimezone(user_tz) if self.date_time else None
            )
        else:
            local_date_time = self.date_time

        return {
            "id": self.id,
            "user_id": self.user_id,
            "date_time": (
                local_date_time.strftime("%Y-%m-%d %H:%M:%S")
                if local_date_time
                else None
            ),
            "act_type": self.act_type,
            "principal_name": self.principal_name,
            "principal_addressLine1": self.principal_addressLine1,
            "principal_addressLine2": self.principal_addressLine2,
            "principal_city": self.principal_city,
            "principal_state": self.principal_state,
            "principal_zipCode": self.principal_zipCode,
            "service_number": self.service_number,
            "service_type": self.service_type,
            "principal_credential_type": self.principal_credential_type,
            "communication_tech": self.communication_tech,
            "certification_authority": self.certification_authority,
            "verification_provider": self.verification_provider,
        }


@app.route("/")
def index():
    return render_template("base.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            return render_template("signup.html", form=form, msg="User already exist")

        role = Role.query.filter_by(id=int(form.options.data)).first()
        session["email"] = form.email.data
        session["password"] = form.password.data
        session["role_id"] = role.id
        print("role.id:", role.id)
        print("session['role_id']:", session["role_id"])

        return redirect(url_for("signup_user_details"))
    return render_template("signup.html", form=form)


@app.route("/signup_user_details", methods=["GET", "POST"])
def signup_user_details():
    form = UserDetailsForm()
    if form.validate_on_submit():
        session["full_name"] = form.full_name.data
        session["street_address_line_one"] = form.street_address_line_one.data
        session["street_address_line_two"] = form.street_address_line_two.data
        session["city"] = form.city.data
        session["state"] = form.state.data
        session["zip_code"] = form.zip_code.data
        session["timezone"] = form.timezone.data

        print("session['role_id']:", session["role_id"])
        role_id = session.get("role_id")
        if role_id in [1]:  # Admin
            return redirect(url_for("signup_admin"))
        elif role_id in [3, 4]:  # Traditional Notary or Electronic Notary
            return redirect(url_for("signup_notary"))
        else:
            return redirect(url_for("confirm_registration"))

    # Prepopulate hidden fields with session data
    form.email.data = session.get("email")
    form.password.data = session.get("password")
    form.role_id.data = session.get("role_id")

    return render_template("signup_user_details.html", form=form)


@app.route("/signup_admin", methods=["GET", "POST"])
def signup_admin():
    form = SignupAdminForm()
    if form.validate_on_submit():
        session["special_code"] = form.special_code.data
        return redirect(url_for("confirm_registration"))

    # Prepopulate hidden fields with session data
    form.email.data = session.get("email")
    form.password.data = session.get("password")
    form.role_id.data = session.get("role_id")
    form.full_name.data = session.get("full_name")
    form.street_address_line_one.data = session.get("street_address_line_one")
    form.street_address_line_two.data = session.get("street_address_line_two")
    form.city.data = session.get("city")
    form.state.data = session.get("state")
    form.zip_code.data = session.get("zip_code")
    form.timezone.data = session.get("timezone")

    return render_template("signup_admin.html", form=form)


@app.route("/signup_notary", methods=["GET", "POST"])
def signup_notary():
    form = SignupNotaryForm()

    if form.validate_on_submit():
        form_data = {
            "email": session.get("email"),
            "password": session.get("password"),
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
        api_data = match_notary_credentials(form_data)
        if api_data is None:
            flash("No matching data found in the API's database", "danger")
            return render_template("signup_notary.html", form=form)

        # Store the form data and API data in the session
        session["commission_holder_name"] = form_data["full_name"]
        session["commission_number_uid"] = form_data["commission_id"]
        session["commissioned_county"] = form_data["commissioned_county"]
        session["commission_start_date"] = form_data["commission_start_date"]
        session["commission_expiration_date"] = form_data["commission_expiration_date"]
        session["commission_type_traditional_or_electronic"] = api_data[
            "commission_type_traditional_or_electronic"
        ]

        return redirect(url_for("confirm_registration"))

    # Set the default value for the email and password fields here, inside the route function
    form.email.data = session.get("email")
    form.password.data = session.get("password")

    return render_template("signup_notary.html", form=form)


@app.route("/confirm_registration", methods=["GET", "POST"])
def confirm_registration():
    form = ConfirmRegistrationForm()
    if form.validate_on_submit():
        user = user_datastore.create_user(
            email=session["email"], password=session["password"]
        )
        role = Role.query.filter_by(id=session["role_id"]).first()
        user_datastore.add_role_to_user(user, role)

        # If special code is in session, assign admin privileges
        if session.get("special_code") == "swordfish":
            admin_role = Role.query.filter_by(name="Admin").first()
            user_datastore.add_role_to_user(user, admin_role)

        # Add user details
        user_details = UserDetails(
            user_id=user.id,
            full_name=session.get("full_name"),
            street_address_line_one=session.get("street_address_line_one"),
            street_address_line_two=session.get("street_address_line_two"),
            city=session.get("city"),
            state=session.get("state"),
            zip_code=session.get("zip_code"),
            timezone=session.get("timezone"),
        )
        db.session.add(user_details)

        # If user is a notary, add notary credentials
        if session["role_id"] in [3, 4]:  # Traditional Notary or Electronic Notary
            notary_credentials = NotaryCredentials(
                user_id=user.id,
                commission_holder_name=session.get("commission_holder_name"),
                commission_number_uid=session.get("commission_number_uid"),
                commissioned_county=session.get("commissioned_county"),
                commission_type_traditional_or_electronic=(
                    "Traditional" if session["role_id"] == 3 else "Electronic"
                ),
                term_issue_date=session.get("commission_start_date"),
                term_expiration_date=session.get("commission_expiration_date"),
            )
            db.session.add(notary_credentials)

        db.session.commit()
        login_user(user)
        return redirect(url_for("index"))

    # Prepopulate hidden fields with session data
    form.email.data = session.get("email")
    form.password.data = session.get("password")
    form.role_id.data = session.get("role_id")
    form.full_name.data = session.get("full_name")
    form.street_address_line_one.data = session.get("street_address_line_one")
    form.street_address_line_two.data = session.get("street_address_line_two")
    form.city.data = session.get("city")
    form.state.data = session.get("state")
    form.zip_code.data = session.get("zip_code")
    form.timezone.data = session.get("timezone")

    if session["role_id"] in [3, 4]:  # Traditional Notary or Electronic Notary
        form.commission_holder_name.data = session.get("commission_holder_name")
        form.commission_number_uid.data = session.get("commission_number_uid")
        form.commissioned_county.data = session.get("commissioned_county")
        form.commission_start_date.data = session.get("commission_start_date")
        form.commission_expiration_date.data = session.get("commission_expiration_date")
        form.commission_type_traditional_or_electronic.data = (
            "Traditional" if session["role_id"] == "3" else "Electronic"
        )

    return render_template("confirm_registration.html", form=form)


@app.route("/signin", methods=["GET", "POST"])
def signin():
    msg = ""
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user:
            if utils.verify_and_update_password(request.form["password"], user):
                login_user(user)
                return redirect(url_for("index"))
            else:
                msg = "Wrong password"
        else:
            msg = "User doesn't exist"
        return render_template("signin.html", msg=msg)
    else:
        return render_template("signin.html", msg=msg)


############################## notary logbook related routes below


@app.route("/notarylogbook")
@roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
def notarylogbook():
    return render_template("mynotarylogbook.html")


@app.route("/notary_log_entry", methods=["GET", "POST"])
def notary_log_entry():
    # Fetch the timezone from the database
    # user_tz = current_user.user_details.timezone
    # form = NotarialActForm(user_tz)
    form = NotarialActForm()
    if form.validate_on_submit():
        # user_tz = pytz.timezone(current_user.user_details.timezone)
        # local_dt = form.date_time.data
        # utc_dt = user_tz.localize(local_dt).astimezone(pytz.utc)
        form_data = form.data.copy()
        form_data.pop("submit", None)
        form_data.pop("csrf_token", None)
        # form_data.pop("timezone", None)
        # form_data["date_time"] = utc_dt
        act = NotarialAct(**form_data)
        db.session.add(act)
        db.session.commit()
        return redirect(url_for("notarylogbook"))
    return render_template(
        "notary_log_entry_form.html", form=form, action=url_for("notary_log_entry")
    )


# 2024-05-28 21:34:20


@app.route("/notary_log_entry/<int:id>", methods=["GET", "POST", "DELETE"])
def handle_notarial_act(id):
    # Fetch the timezone from the database
    # user_tz = current_user.user_details.timezone
    act = NotarialAct.query.get(id)
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
    query = NotarialAct.query

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
    return render_template("principals.html", principals=principals)


@app.route("/trad_notaries")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def trad_notaries():
    trad_notaries = ["oldmannotary@aol.com", "papyrus@friendster.com"]
    role_trad_notaries = db.session.query(roles_users).filter_by(role_id=3)
    for trad_notary in role_trad_notaries:
        user = User.query.filter_by(id=trad_notary.user_id).first()
        trad_notaries.append(user.email)
    return render_template("traditionalnotaries.html", trad_notaries=trad_notaries)


@app.route("/e_notaries")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def e_notaries():
    e_notaries = ["amazo@gmail.com", "thefuture@yahoo.com"]
    role_e_notaries = db.session.query(roles_users).filter_by(role_id=4)
    for e_notary in role_e_notaries:
        user = User.query.filter_by(id=e_notary.user_id).first()
        e_notaries.append(user.email)
    return render_template("electronicnotaries.html", e_notaries=e_notaries)


@app.route("/mydetails")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def mydetails():
    return render_template("mydetails.html")


@app.route("/mydocuments", methods=["GET", "POST"])
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def mydocuments():
    form = UploadDocumentForm()
    if form.validate_on_submit():
        f = form.document.data
        filename = secure_filename(f.filename)

        # Create a Cloud Storage client.
        gcs = storage.Client()

        # Get the bucket that the file will be uploaded to.
        bucket = gcs.get_bucket(current_app.config["NOTARIOUS_TEST_BUCKET"])

        # Create a new blob and upload the file's content.
        blob = bucket.blob(filename)
        blob.upload_from_string(f.read(), content_type=f.content_type)

        # Make the blob publicly viewable.
        blob.make_public()

        # The URL can be used to directly access the uploaded file.
        file_url = blob.public_url
        # Create a new PDFDocument object
        document = PDFDocument(
            filename=filename,
            file_url=file_url,
            user_id=current_user.id,
            size=blob.size,
            content_type=f.content_type,
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
    return render_template("mydocuments.html", form=form)


@app.route("/findnotary")
# @roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def findnotary():
    return render_template("findnotary.html")


@app.route("/resourcecenter")
# @roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def resourcecenter():
    return render_template("resourcecenter.html")


@app.route("/myesignature")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def myesignature():
    return render_template("myesignature.html")


if __name__ == "__main__":
    app.run(debug=True)
