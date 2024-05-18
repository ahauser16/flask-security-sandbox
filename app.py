from flask import Flask, render_template, redirect, url_for, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_security import (
    UserMixin,
    RoleMixin,
    Security,
    SQLAlchemySessionUserDatastore,
    SQLAlchemyUserDatastore,
    roles_accepted,
)
from flask_login import LoginManager, login_manager, login_user, current_user
from flask_migrate import Migrate
import requests
from datetime import datetime
import urllib.parse

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///nysdos_notaries_test"
app.config["SECRET_KEY"] = "count_duckula"
app.config["SECURITY_PASSWORD_SALT"] = "count_duckula"
app.config["SECURITY_REGISTERABLE"] = True
app.config["SECURITY_SEND_REGISTER_EMAIL"] = False

db = SQLAlchemy()
db.init_app(app)

migrate = Migrate(app, db)  # Initialize Migrate after db

app.app_context().push()

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


class NotaryCredentials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    commission_holder_name = db.Column(db.String(100))
    commission_number_uid = db.Column(db.String(100))
    commissioned_county = db.Column(db.String(100))
    commission_type_traditional_or_electronic = db.Column(db.String(100))
    term_issue_date = db.Column(db.DateTime)
    term_expiration_date = db.Column(db.DateTime)
    user = db.relationship("User", backref="notary_credentials_backref", uselist=False)


user_datastore = SQLAlchemySessionUserDatastore(db.session, User, Role)
security = Security(app, user_datastore)


@app.before_first_request
def create_tables():
    db.create_all()


@app.route("/")
def index():
    return render_template("base.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    msg = ""
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user:
            msg = "User already exist"
            return render_template("signup.html", msg=msg)

        session["email"] = request.form["email"]
        session["password"] = request.form["password"]
        session["role_id"] = request.form["options"]

        role = Role.query.filter_by(id=session["role_id"]).first()
        if role.name in ["Traditional Notary", "Electronic Notary"]:
            return redirect(url_for("notaryauth"))
        else:
            user = User(email=session["email"], active=1, password=session["password"])
            user.roles.append(role)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for("index"))
    else:
        return render_template("signup.html", msg=msg)


@app.route("/notaryauth", methods=["GET", "POST"])
def notaryauth():
    # If the HTTP method is `POST`, it means the user has submitted the form on the `signupnotary.html` page. The function then retrieves the form data.
    if request.method == "POST":
        full_name = request.form["full_name"]
        commission_id = request.form["commission_id"]
        commissioned_county = request.form["commissioned_county"]
        commission_start_date = datetime.strptime(
            request.form["commission_start_date"], "%Y-%m-%d"
        )
        commission_expiration_date = datetime.strptime(
            request.form["commission_expiration_date"], "%Y-%m-%d"
        )

        # Convert dates back to string format
        commission_start_date_str = commission_start_date.strftime("%Y-%m-%d")
        commission_expiration_date_str = commission_expiration_date.strftime("%Y-%m-%d")

        # Define a mapping between the radio button values and the API values
        role_mapping = {
            3: "Traditional",
            4: "Electronic",
        }

        # Get the role value from the form
        role_value = int(session["role_id"])

        # Get the corresponding string value for the API
        commission_type = role_mapping.get(role_value)

        # URL encode the commission_id
        commission_id_encoded = urllib.parse.quote_plus(commission_id)

        # The function then sends a GET request to an API endpoint with the commission_id as a parameter.
        response = requests.get(
            "https://data.ny.gov/resource/rwbv-mz6z.json",
            params={
                "commission_holder_name": full_name,
                "commission_number_uid": commission_id_encoded,
                "commissioned_county": commissioned_county,
                "commission_type_traditional_or_electronic": commission_type,
                "term_issue_date": commission_start_date_str,
                "term_expiration_date": commission_expiration_date_str,
            },
        )
        data = response.json()
        print("Data from API: ", data)

        # If the API response is empty, not a list, or has no elements, the function returns an error message.
        if not data or not isinstance(data, list) or len(data) == 0:
            return (
                jsonify({"error": "No matching data found in the API's database"}),
                400,
            )

        print(
            "Data to map to: ",
            full_name,
            commissioned_county,
            commission_start_date,
            commission_expiration_date,
        )

        # The function then creates a SQLAlchemyUserDatastore instance, which is used to interact with the database.
        user_datastore = SQLAlchemyUserDatastore(db, User, Role)
        # If the user data matches the data from the API, the function creates a new user with the email and password stored in the session, assigns the user a role based on the commission_type_traditional_or_electronic field, commits the changes to the database, logs the user in, and redirects them to the index page.
        if (
            data[0]["commission_holder_name"].lower() == full_name.lower()
            and data[0]["commissioned_county"].lower() == commissioned_county.lower()
            and datetime.strptime(data[0]["term_issue_date"], "%Y-%m-%dT%H:%M:%S.%f")
            == commission_start_date
            and datetime.strptime(
                data[0]["term_expiration_date"], "%Y-%m-%dT%H:%M:%S.%f"
            )
            == commission_expiration_date
        ):
            user = user_datastore.create_user(
                email=session["email"], password=session["password"]
            )
            role = user_datastore.find_role(
                "Traditional Notary"
                if data[0]["commission_type_traditional_or_electronic"] == "Traditional"
                else "Electronic Notary"
            )

            user_datastore.add_role_to_user(user, role)

            # Create a new NotaryCredentials instance and associate it with the user
            notary_credentials = NotaryCredentials(
                user_id=user.id,
                commission_holder_name=full_name,
                commission_number_uid=commission_id,
                commissioned_county=commissioned_county,
                commission_type_traditional_or_electronic=commission_type,
                term_issue_date=commission_start_date,
                term_expiration_date=commission_expiration_date,
            )
            db.session.add(notary_credentials)

            db.session.commit()
            login_user(user)
            return redirect(url_for("index"))
        else:
            # If the user data does not match the data from the API, the function re-renders the `signupnotary.html` page with an error message.
            return render_template(
                "signupnotary.html",
                error="The provided data does not match the API's database",
            )

    else:
        # If the HTTP method is not POST (i.e., it's a GET request), the function simply renders the signupnotary.html page.
        return render_template("signupnotary.html")


@app.route("/signin", methods=["GET", "POST"])
def signin():
    msg = ""
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user:
            if user.password == request.form["password"]:
                login_user(user)
                return redirect(url_for("index"))
            else:
                msg = "Wrong password"

        else:
            msg = "User doesn't exist"
        return render_template("signin.html", msg=msg)

    else:
        return render_template("signin.html", msg=msg)


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
    return render_template("mynotarylogbook.html")


@app.route("/myesignature")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def myesignature():
    return render_template("myesignature.html")


if __name__ == "__main__":
    app.run(debug=True)
