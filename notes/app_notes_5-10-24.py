from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_security import (
    UserMixin,
    RoleMixin,
    Security,
    SQLAlchemySessionUserDatastore,
    roles_accepted,
)
from flask_login import LoginManager, login_manager, login_user

# pass current module (__name__) as argument to `Flask()` which will initialize the instance
app = Flask(__name__)

# path to psql database which will create the db file in instance if the db is not  already present
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///flask_rbac_tutorial"
# needed for session cookies
app.config["SECRET_KEY"] = "count_duckula"
# hashes the password and then stores in the database
app.config["SECURITY_PASSWORD_SALT"] = "MY_SECRET"
# allows new registrations to application
app.config["SECURITY_REGISTERABLE"] = True
# to send automatic registration email to user
app.config["SECURITY_SEND_REGISTER_EMAIL"] = False

db = SQLAlchemy()
db.init_app(app)

# runs the app instance
app.app_context().push()

# create table in database for assigning roles
roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
)

# create table in database for storing users
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String(255), nullable=False, server_default="")
    active = db.Column(db.Boolean())
    # backreferences the user_id from roles_users table
    roles = db.relationship("Role", secondary=roles_users, backref="roled")


# create table in database for storing roles
class Role(db.Model, RoleMixin):
    __tablename__ = "role"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)


# load users, roles for a session
user_datastore = SQLAlchemySessionUserDatastore(db.session, User, Role)
security = Security(app, user_datastore)


# creates all database tables
@app.before_first_request
def create_tables():
    db.create_all()


# ‘/’ URL is bound with index() function.
@app.route("/")
# defining function index which returns the rendered html code for our home page
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    msg = ""
    # if the form is submitted
    if request.method == "POST":
        # check if user already exists
        user = User.query.filter_by(email=request.form["email"]).first()
        msg = ""
        # if user already exists render the msg
        if user:
            msg = "User already exist"
            # render signup.html if user exists
            return render_template("signup.html", msg=msg)

        # if user doesn't exist

        # store the user to database
        user = User(
            email=request.form["email"], active=1, password=request.form["password"]
        )
        # store the role
        role = Role.query.filter_by(id=request.form["options"]).first()
        user.roles.append(role)

        # commit the changes to database
        db.session.add(user)
        db.session.commit()

        # login the user to the app
        # this user is current user
        login_user(user)
        # redirect to index page
        return redirect(url_for("index"))

    # case other than submitting form, like loading the page itself
    else:
        return render_template("signup.html", msg=msg)


# signin page
@app.route("/signin", methods=["GET", "POST"])
def signin():
    msg = ""
    if request.method == "POST":
        # search user in database
        user = User.query.filter_by(email=request.form["email"]).first()
        # if exist check password
        if user:
            if user.password == request.form["password"]:
                # if password matches, login the user
                login_user(user)
                return redirect(url_for("index"))
            # if password doesn't match
            else:
                msg = "Wrong password"

        # if user does not exist
        else:
            msg = "User doesn't exist"
        return render_template("signin.html", msg=msg)

    else:
        return render_template("signin.html", msg=msg)


@app.route("/teachers")
@roles_accepted("Admin")
def teachers():
    teachers = ["teacher@abc.com", "teacher1@abc.com", "teacher1000@abc.com"]
    # query for role Teacher that is role_id=2
    role_teachers = db.session.query(roles_users).filter_by(role_id=2)
    # query for the users' details using user_id
    for teacher in role_teachers:
        user = User.query.filter_by(id=teacher.user_id).first()
        teachers.append(user)
    # return the teachers list
    return render_template("teachers.html", teachers=teachers)


# for staff page
@app.route("/staff")
# only Admin and Teacher can access the page
@roles_accepted("Admin", "Teacher")
def staff():
    staff = []
    role_staff = db.session.query(roles_users).filter_by(role_id=3)
    for staf in role_staff:
        user = User.query.filter_by(id=staf.user_id).first()
        staff.append(user)
    return render_template("staff.html", staff=staff)


# for student page
@app.route("/students")
# only Admin, Teacher and Staff can access the page
@roles_accepted("Admin", "Teacher", "Staff")
def students():
    students = []
    role_students = db.session.query(roles_users).filter_by(role_id=4)
    for student in role_students:
        user = User.query.filter_by(id=student.user_id).first()
        students.append(user)
    return render_template("students.html", students=students)


# for details page
@app.route("/mydetails")
# Admin, Teacher, Staff and Student can access the page
@roles_accepted("Admin", "Teacher", "Staff", "Student")
def mydetails():
    return render_template("mydetails.html")

@app.route("/teacherslounge")
@roles_accepted("Admin", "Teacher")
def teacherslounge():
    return render_template("teacherslounge.html")


if __name__ == "__main__":
    app.run(debug=True)
