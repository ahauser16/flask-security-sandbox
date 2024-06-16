from . import db
from .user import User
from .document_role import DocumentRole
from models.database import document_role_documents
from datetime import datetime

class PDFDocument(db.Model):
    __tablename__ = "pdf_document"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    filepath = db.Column(db.String(500))  
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(10), nullable=False, default="Unsigned")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref="pdf_documents")
    size = db.Column(db.Integer)  
    content_type = db.Column(db.String(100))  
    notes = db.Column(db.String(500))  
    document_roles = db.relationship(
        "DocumentRole", secondary=document_role_documents, backref="pdf_documents"
    )
    
    # Explanation: In this case, you're importing the db object from your __init__.py file, which is where it's initialized. This allows all parts of your application to use the same db object, which is necessary for SQLAlchemy to track changes to your models correctly. The PDFDocument class is a SQLAlchemy model that represents the pdf_document table in your database. The id column is the primary key, and the other columns represent various details about the PDF document. The user relationship establishes a link to the User model, which allows you to access the user associated with a particular PDF document. The document_roles relationship establishes a link to the DocumentRole model through the document_role_documents association table, which allows you to access the document roles associated with a particular PDF document.