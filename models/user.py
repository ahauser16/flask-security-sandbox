# user.py
from flask_security import UserMixin
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Table
from models.database import db, document_role_users, roles_users


class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String(255), nullable=False, server_default="")
    active = db.Column(db.Boolean())
    roles = db.relationship("Role", secondary=roles_users, backref="roled")
    notary_credentials = db.relationship(
        "NotaryCredentials", backref="notary_credentials", uselist=False
    )
    user_details = db.relationship("UserDetails", backref="user_details", uselist=False)
    employer_id = db.Column(
        db.Integer, db.ForeignKey("employer_details.id"), nullable=True
    )  # This field establishes the foreign key relationship to the EmployerDetails table, indicating which employer a user is associated with.
    document_roles = db.relationship(
        "DocumentRole", secondary=document_role_users, backref="users"
    )  # The document_roles field is a relationship field that links a user or a document to its roles. The secondary parameter specifies the association table that links the user and document roles.
    employer = db.relationship("EmployerDetails", backref="user_details", uselist=False)


# In the EmployerDetails model, the users relationship uses the backref argument to create a reverse reference from the User model. This means each User instance will have an employer attribute that points to their EmployerDetails instance. The lazy='True' option is used to load the related User instances on access lazily.  This setup allows a one-to-many relationship where each user can have one employer, and each employer can have multiple users.
