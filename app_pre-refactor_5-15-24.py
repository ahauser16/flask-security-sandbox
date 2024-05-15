from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_security import (
    UserMixin,
    RoleMixin,
    Security,
    SQLAlchemySessionUserDatastore,
    roles_accepted,
)
from flask_login import LoginManager, login_manager, login_user
import requests

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


@app.route("/signup", methods=["GET", "POST"])
def signup():
    msg = ""
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        msg = ""
        if user:
            msg = "User already exist"
            return render_template("signup.html", msg=msg)

        user = User(
            email=request.form["email"], active=1, password=request.form["password"]
        )
        role = Role.query.filter_by(id=request.form["options"]).first()
        user.roles.append(role)

        db.session.add(user)
        db.session.commit()

        login_user(user)
        # return redirect(url_for("index"))
        # below is a refactor to attempt to authenticate the user's notary public commission.
        if role.name in ["Traditional Notary", "Electronic Notary"]:
            return redirect(url_for("notaryauth"))
        else:
            return redirect(url_for("index"))

    else:
        return render_template("signup.html", msg=msg)


@app.route("/notaryauth", methods=["GET", "POST"])
@roles_accepted("Traditional Notary", "Electronic Notary")
def notaryauth():
    if request.method == "POST":
        full_name = request.form["full_name"]
        commission_id = request.form["commission_id"]
        commissioned_county = request.form["commissioned_county"]
        commission_start_date = request.form["commission_start_date"]
        commission_expiration_date = request.form["commission_expiration_date"]

        response = requests.get(
            "https://data.ny.gov/resource/rwbv-mz6z.json",
            params={"commission_id": commission_id},
        )
        data = response.json()

        if not data or not isinstance(data, list) or len(data) == 0:
            return (
                jsonify({"error": "No matching data found in the API's database"}),
                400,
            )

        user_data = data[0]
        if (
            user_data["full_name"] == full_name
            and user_data["commissioned_county"] == commissioned_county
            and user_data["commission_start_date"] == commission_start_date
            and user_data["commission_expiration_date"] == commission_expiration_date
        ):
            return redirect(url_for("index"))
        else:
            return (
                jsonify(
                    {"error": "The provided data does not match the API's database"}
                ),
                400,
            )

    else:
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
