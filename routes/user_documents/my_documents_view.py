# routes/user_documents/my_documents_view.py
from flask import Blueprint, render_template
from flask_security import roles_accepted, current_user
from models import PDFDocument
from forms import DeleteDocumentForm

my_documents_view_bp = Blueprint("my_documents_view", __name__)

@my_documents_view_bp.route("/mydocuments", methods=["GET"])
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def mydocuments():
    # Query the documents from the database
    documents = PDFDocument.query.filter_by(user_id=current_user.id).all()
    delete_document_form = DeleteDocumentForm()
    return render_template(
        "documents/mydocuments.html",
        documents=documents,
        delete_document_form=delete_document_form,
    )