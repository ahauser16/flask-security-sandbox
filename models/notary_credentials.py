from . import db
from .user import User


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
    user = db.relationship("User", backref="user_notary_credentials", uselist=False)

# Explanation: In this case, you're importing the db object from your __init__.py file, which is where it's initialized. This allows all parts of your application to use the same db object, which is necessary for SQLAlchemy to track changes to your models correctly. The NotaryCredentials class is a SQLAlchemy model that represents the notary_credentials table in your database. The id column is the primary key, and the user_id column is a foreign key that references the id column in the user table. The other columns represent various details about the notary credentials. The user relationship establishes a link to the User model, which allows you to access the user associated with a particular set of notary credentials.