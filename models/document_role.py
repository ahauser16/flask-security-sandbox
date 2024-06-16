from . import db

class DocumentRole(db.Model):
    __tablename__ = "document_role"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    
    # Expalanation: The document_roles field is a relationship field that links a user or a document to its roles.  In this case, you're importing the db object from your __init__.py file, which is where it's initialized. This allows all parts of your application to use the same db object, which is necessary for SQLAlchemy to track changes to your models correctly. The DocumentRole class is a SQLAlchemy model that represents the document_role table in your database. The id and name are columns in the table. The id column is the primary key, and the name column is unique, which means that no two document roles can have the same name. The document_roles relationship field establishes a link to the PDFDocument model through the document_role_documents association table, which allows you to access the PDF documents associated with a particular document role. 