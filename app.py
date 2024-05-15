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
from flask_login import LoginManager, login_manager, login_user
import requests
from datetime import datetime


app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///nysdos_notaries_test"
app.config["SECRET_KEY"] = "count_duckula"
app.config["SECURITY_PASSWORD_SALT"] = "count_duckula"
app.config["SECURITY_REGISTERABLE"] = True
app.config["SECURITY_SEND_REGISTER_EMAIL"] = False

db = SQLAlchemy()
db.init_app(app)

app.app_context().push()

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


class Role(db.Model, RoleMixin):
    __tablename__ = "role"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)


user_datastore = SQLAlchemySessionUserDatastore(db.session, User, Role)
security = Security(app, user_datastore)


@app.before_first_request
def create_tables():
    db.create_all()


@app.route("/")
def index():
    return render_template("index.html")


# This line sets up a route for the `/signup` URL. It accepts both GET and POST requests.
@app.route("/signup", methods=["GET", "POST"])
# This line defines the function that will be executed when the /signup route is accessed.
def signup():
    # This line initializes a variable `msg` to an empty string. This variable is used to store any message that needs to be displayed to the user.
    msg = ""
    # This line checks if the request method is `POST`, which means the user has submitted the signup form.
    if request.method == "POST":
        # This line queries the database to check if a user with the submitted email already exists.
        user = User.query.filter_by(email=request.form["email"]).first()
        # This line checks if a user was found in the previous step.
        if user:
            # If a user was found, this line sets the `msg` variable to "User already exist".
            msg = "User already exist"
            # This line renders the signup form again, passing the `msg` variable to the template.
            return render_template("signup.html", msg=msg)

        # This line stores the submitted email in the session.
        session["email"] = request.form["email"]
        # This line stores the submitted password in the session.
        session["password"] = request.form["password"]
        # This line stores the submitted role ID in the session.
        session["role_id"] = request.form["options"]

        # This line queries the database to get the role object corresponding to the submitted role ID.
        role = Role.query.filter_by(id=session["role_id"]).first()
        # This line checks if the role name is either "Traditional Notary" or "Electronic Notary".
        if role.name in ["Traditional Notary", "Electronic Notary"]:
            # If the role name is either "Traditional Notary" or "Electronic Notary", this line redirects the user to the `/notaryauth` route.
            return redirect(url_for("notaryauth"))
        else:
            # If the role name is not either "Traditional Notary" or "Electronic Notary", this line creates a new user object with the submitted email and password, and sets the active attribute to 1.
            user = User(email=session["email"], active=1, password=session["password"])
            # This line adds the role to the user's roles.
            user.roles.append(role)
            # This line adds the user object to the session.
            db.session.add(user)
            # This line commits the session, which saves the user to the database.
            db.session.commit()
            # This line logs the user in.
            login_user(user)
            # This line redirects the user to the `/index` route.
            return redirect(url_for("index"))
    # This line starts the else block, which is executed if the request method is not POST.
    else:
        # This line renders the signup form, passing the msg variable to the template.
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
        # commission_type = request.form["commission_type_traditional_or_electronic"]

        # Convert dates back to string format
        commission_start_date_str = commission_start_date.strftime("%Y-%m-%d")
        commission_expiration_date_str = commission_expiration_date.strftime("%Y-%m-%d")

        # The function then sends a GET request to an API endpoint with the commission_id as a parameter.
        response = requests.get(
            "https://data.ny.gov/resource/rwbv-mz6z.json",
            params={
                "commission_holder_name": full_name,
                "commission_number_uid": commission_id,
                "commissioned_county": commissioned_county,
                # "commission_type_traditional_or_electronic": commission_type,
                "term_issue_date": commission_start_date_str,
                "term_expiration_date": commission_expiration_date_str,
            },
        )
        data = response.json()
        print(data)

        # If the API response is empty, not a list, or has no elements, the function returns an error message.
        if not data or not isinstance(data, list) or len(data) == 0:
            return (
                jsonify({"error": "No matching data found in the API's database"}),
                400,
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


@app.route("/mytradnotarylog")
@roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
def mytradnotarylog():
    return render_template("mytradnotarylog.html")


@app.route("/myenotarylog")
@roles_accepted("Admin", "Electronic Notary")
def myenotarylog():
    return render_template("myenotarylog.html")


@app.route("/myesignature")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def myesignature():
    return render_template("myesignature.html")


if __name__ == "__main__":
    app.run(debug=True)
