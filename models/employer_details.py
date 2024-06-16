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
    users = db.relationship("User", backref="employer", lazy=True)
    
    # Explanation: In this case, you're importing the db object from your __init__.py file, which is where it's initialized. This allows all parts of your application to use the same db object, which is necessary for SQLAlchemy to track changes to your models correctly. The EmployerDetails class is a SQLAlchemy model that represents the employer_details table in your database. The id column is the primary key, and the other columns represent various details about the employer. The users relationship establishes a link to the User model, which allows you to access the users associated with a particular employer.