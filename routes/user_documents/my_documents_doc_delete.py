# routes/user_documents/my_documents_doc_delete.py
from flask import Blueprint, abort, redirect, url_for
from flask_security import roles_accepted
from models import PDFDocument
import os
from models.database import db


my_documents_doc_delete_bp = Blueprint("my_documents_doc_delete", __name__)

@my_documents_doc_delete_bp.route("/delete_document/<int:document_id>", methods=["POST"])
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def delete_document(document_id):
    # Query the document from the database
    document = PDFDocument.query.get(document_id)
    if document is None:
        abort(404)  # Not found

    # Delete the file from the file system
    os.remove(document.filepath)

    # Delete the document from the database
    db.session.delete(document)
    db.session.commit()

    return redirect(url_for("mydocuments"))