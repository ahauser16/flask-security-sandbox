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
    employer_id = db.Column(db.Integer, db.ForeignKey("employer_details.id"), nullable=True)

    # The document_roles field is a relationship field that links a user or a document to its roles.
    document_roles = db.relationship(
        "DocumentRole", secondary=document_role_users, backref="users"
    )
    employer = db.relationship("EmployerDetails", backref="user", uselist=False)
