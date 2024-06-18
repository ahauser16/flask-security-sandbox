# routes/user_documents/my_documents_doc_view.py
from flask import Blueprint, abort, render_template
from flask_security import roles_accepted
from models import PDFDocument

my_documents_doc_view_bp = Blueprint("my_documents_doc_view", __name__)

@my_documents_doc_view_bp.route("/view_document/<int:document_id>")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def view_document(document_id):
    # Query the document from the database
    document = PDFDocument.query.get(document_id)
    if document is None:
        abort(404)  # Not found

    # Render the view_document.html template
    return render_template("documents/view_document.html", document=document)