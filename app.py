from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    jsonify,
    session,
    abort,
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
import requests
import logging
from datetime import datetime
import urllib.parse

from forms.signup_forms import (
    SignupForm,
    SignupPrincipalForm,
    SignupAdminForm,
    SignupNotaryForm,
    ConfirmRegistrationForm,
    UserDetailsForm,
)

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


# role_users must be defined before the User and Role classes
roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
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


class Role(db.Model, RoleMixin):
    __tablename__ = "role"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)


# Now that User and Role are defined, we can create the user_datastore and security
user_datastore = SQLAlchemySessionUserDatastore(db.session, User, Role)
security = Security(app, user_datastore)


class UserDetails(db.Model):
    __tablename__ = "user_details"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    full_name = db.Column(db.String(100), nullable=False)
    street_address_line_one = db.Column(db.String(255), nullable=False)
    street_address_line_two = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(2), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    user = db.relationship("User", backref="details", uselist=False)


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
    date = db.Column(db.DateTime)
    time = db.Column(db.Time)
    act_type = db.Column(db.String(100))
    other_act_type_input = db.Column(db.String(100), nullable=True)
    principal_name = db.Column(db.String(100))
    principal_addressLine1 = db.Column(db.String(100))
    principal_addressLine2 = db.Column(db.String(100))
    principal_city = db.Column(db.String(100))
    principal_state = db.Column(db.String(2))
    principal_zipCode = db.Column(db.String(100))
    service_number = db.Column(db.Integer)
    service_type = db.Column(db.String(100))
    credential_type = db.Column(db.String(100))
    communication_tech = db.Column(db.String(100), nullable=True)
    certification_authority = db.Column(db.String(100), nullable=True)
    verification_provider = db.Column(db.String(100), nullable=True)
    user = db.relationship("User", backref=db.backref("notarial_acts", lazy=True))

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "date": self.date,
            "time": self.time,
            "act_type": self.act_type,
            "other_act_type_input": self.other_act_type_input,
            "principal_name": self.principal_name,
            "principal_addressLine1": self.principal_addressLine1,
            "principal_addressLine2": self.principal_addressLine2,
            "principal_city": self.principal_city,
            "principal_state": self.principal_state,
            "principal_zipCode": self.principal_zipCode,
            "service_number": self.service_number,
            "service_type": self.service_type,
            "credential_type": self.credential_type,
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

        role = Role.query.filter_by(id=form.options.data).first()
        session["email"] = form.email.data
        session["password"] = form.password.data
        session["role_id"] = role.id

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

        role_id = session.get("role_id")
        if role_id in [3, 4]:  # Traditional Notary or Electronic Notary
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
        return redirect(url_for("confirm_registration"))

    # Set the default value for the email field here, inside the route function
    form.email.data = session.get("email")
    form.password.data = session.get("password")

    return render_template("signup_admin.html", form=form)


@app.route("/signup_principal", methods=["GET", "POST"])
def signup_principal():
    form = SignupPrincipalForm()

    if form.validate_on_submit():
        return redirect(url_for("confirm_registration"))

    # Set the default value for the email field here, inside the route function
    form.email.data = session.get("email")
    form.password.data = session.get("password")

    return render_template("signup_principal.html", form=form)


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
        session["full_name"] = form_data["full_name"]
        session["commission_id"] = form_data["commission_id"]
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

        # Add user details
        user_details = UserDetails(
            user_id=user.id,
            full_name=session.get("full_name"),
            street_address_line_one=session.get("street_address_line_one"),
            street_address_line_two=session.get("street_address_line_two"),
            city=session.get("city"),
            state=session.get("state"),
            zip_code=session.get("zip_code"),
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

    if session["role_id"] in [3, 4]:  # Traditional Notary or Electronic Notary
        form.commission_holder_name.data = session.get("commission_holder_name")
        form.commission_number_uid.data = session.get("commission_number_uid")
        form.commissioned_county.data = session.get("commissioned_county")
        form.commission_start_date.data = session.get("commission_start_date")
        form.commission_expiration_date.data = session.get("commission_expiration_date")
        form.commission_type_traditional_or_electronic.data = (
            "Traditional" if session["role_id"] == "3" else "Electronic"
        )

    return render_template("signup_final.html", form=form)


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


############################ new code below
@app.route("/api/notarial_act_data")
def notarial_act_data():
    query = NotarialAct.query.filter_by(user_id=current_user.id)

    # search filter
    search = request.args.get("search")
    if search:
        query = query.filter(NotarialAct.act_type.like(f"%{search}%"))

    total = query.count()

    # sorting
    sort = request.args.get("sort")
    if sort:
        order = []
        for s in sort.split(","):
            direction = s[0]
            name = s[1:]
            if name not in ["date", "time", "act_type"]:
                name = "date"
            col = getattr(NotarialAct, name)
            if direction == "-":
                col = col.desc()
            order.append(col)
        if order:
            query = query.order_by(*order)

    # pagination
    start = request.args.get("start", type=int, default=-1)
    length = request.args.get("length", type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    return {
        "data": [act.to_dict() for act in query],
        "total": total,
    }


@app.route("/api/notarial_act_data", methods=["POST"])
def update_notarial_act():
    data = request.get_json()
    if "id" not in data:
        abort(400)
    act = NotarialAct.query.get(data["id"])
    for field in ["date", "time", "act_type"]:
        if field in data:
            setattr(act, field, data[field])
    db.session.commit()
    return "", 204


############################ new code above


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


@app.route("/notarylogbook")
@roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
def notarylogbook():
    return render_template(
        "mynotarylogbook.html", notarial_acts=current_user.notarial_acts
    )


@app.route("/addnotarylogentry", methods=["GET", "POST"])
def add_notary_log_entry():
    if request.method == "POST":
        act = NotarialAct(
            date=request.form.get("date"),
            time=request.form.get("time"),
            act_type=request.form.get("act_type"),
            other_act_type_input=request.form.get("other_act_type_input"),
            principal_name=request.form.get("principal_name"),
            principal_addressLine1=request.form.get("principal_addressLine1"),
            principal_addressLine2=request.form.get("principal_addressLine2"),
            principal_city=request.form.get("principal_city"),
            principal_state=request.form.get("principal_state"),
            principal_zipCode=request.form.get("principal_zipCode"),
            service_number=request.form.get("service_number"),
            service_type=request.form.get("service_type"),
            credential_type=request.form.get("credential_type"),
            communication_tech=request.form.get("communication_tech"),
            certification_authority=request.form.get("certification_authority"),
            verification_provider=request.form.get("verification_provider"),
        )
        db.session.add(act)
        db.session.commit()
    return render_template("addnotarialactform.html")


@app.route("/findnotary")
# @roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def findnotary():
    return render_template("findnotary.html")


@app.route("/myesignature")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def myesignature():
    return render_template("myesignature.html")


if __name__ == "__main__":
    app.run(debug=True)
