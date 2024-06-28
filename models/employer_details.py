# models/employer_details.py
from . import db
from .user import User


class EmployerDetails(db.Model):
    __tablename__ = "employer_details"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    street_address_line_one = db.Column(db.String(255), nullable=False)
    street_address_line_two = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(2), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    ein_number = db.Column(db.String(20), nullable=False, unique=True)
    users = db.relationship(
        "User", backref="employer_details", lazy=True
    )  # This adds a 'users' collection to EmployerDetails instances and a 'employer' backref to User instances

    @staticmethod
    def find_by_ein(ein_number):
        return EmployerDetails.query.filter_by(ein_number=ein_number).first()
