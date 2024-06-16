from . import db

class UserDetails(db.Model):
    __tablename__ = "user_details"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    timezone = db.Column(db.String(50), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    street_address_line_one = db.Column(db.String(255), nullable=False)
    street_address_line_two = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(2), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    
    # Explanation: In this case, you're importing the db object from your __init__.py file, which is where it's initialized. This allows all parts of your application to use the same db object, which is necessary for SQLAlchemy to track changes to your models correctly. The UserDetails class is a SQLAlchemy model that represents the user_details table in your database. The id column is the primary key, and the user_id column is a foreign key that references the id column in the user table. The other columns represent various details about the user. The user relationship establishes a link to the User model, which allows you to access the user associated with a particular set of user details. 