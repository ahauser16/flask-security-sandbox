# app.py
from flask import (
    Flask,
    render_template,
)
from flask_security import (
    Security,
    SQLAlchemySessionUserDatastore,
    roles_accepted,
)
from flask_login import current_user
from flask_migrate import Migrate
from google.cloud import storage
import logging
from datetime import datetime


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
# `create_tables` calls `db.create_all()` to create all tables in the database according to the schema defined in the models. This is essential for initializing the database with the necessary structure before any data can be inserted or queried.
def create_tables():
    db.create_all()

    # Populate Roles Table: the cod ebelow checks if there are any entries in the `Role` table by querying the first entry with Role.query.first(). If no entries exist (indicating the table is empty), it proceeds to create a list of `Role` objects with predefined id and name attributes. These objects represent different user roles such as "Admin", "Principal", "Traditional Notary", and "Electronic Notary". Each `Role` object is then added to the `session` with `db.session.add(role)`, and after all roles are added, the `session` is committed to the database with `db.session.commit()`, effectively saving these roles in the `Role` table. A success message is printed to indicate the roles were created successfully.
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

    # Populate Document Roles Table: this code checks if the `DocumentRole` table is empty. If so, it creates a list of `DocumentRole` objects, each representing a document role with predefined `id` and `name` attributes. These objects are added to the `session` and committed to the database in the same manner as the `Role` objects. A success message is printed to indicate the document roles were created successfully.
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


if __name__ == "__main__":
    app.run(debug=True)
