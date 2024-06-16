# role.py
from flask_security import RoleMixin
from . import db

class Role(db.Model, RoleMixin):
    __tablename__ = "role"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    
    # In this case, you're importing the db object from your __init__.py file, which is where it's initialized. This is a common pattern in Flask applications, where the db object is initialized in a central location and then imported where it's needed. This allows all parts of your application to use the same db object, which is necessary for SQLAlchemy to track changes to your models correctly. The Role class is a SQLAlchemy model that represents the role table in your database. The id and name are columns in the table. The id column is the primary key, and the name column is unique, which means that no two roles can have the same name. The RoleMixin class provides methods that are useful for working with roles in Flask-Security, such as checking if a user has a particular role. 