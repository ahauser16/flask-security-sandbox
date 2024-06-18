# routes/user_documents/my_documents_doc_download.py
from flask import Blueprint, current_app, abort, send_from_directory
from flask_security import roles_accepted
from models import PDFDocument
import os

my_documents_doc_download_bp = Blueprint("my_documents_doc_download", __name__)

@my_documents_doc_download_bp.route("/download_document/<int:document_id>")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def download_document(document_id):
    # Query the document from the database
    document = PDFDocument.query.get(document_id)
    if document is None:
        abort(404)  # Not found

    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], document.filename)
    print(f"File path: {file_path}")  # Print the file path

    if not os.path.isfile(file_path):
        print(
            f"File does not exist: {file_path}"
        )  # Print a message if the file does not exist

    # Send the file to the client
    return send_from_directory(current_app.config["UPLOAD_FOLDER"], document.filename)