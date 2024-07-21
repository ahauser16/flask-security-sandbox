# models/database.py
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
)

document_role_documents = db.Table(
    "document_role_documents",
    db.Column("pdf_document_id", db.Integer(), db.ForeignKey("pdf_document.id")),
    db.Column("document_role_id", db.Integer(), db.ForeignKey("document_role.id")),
)

document_role_users = db.Table(
    "document_role_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("document_role_id", db.Integer(), db.ForeignKey("document_role.id")),
)