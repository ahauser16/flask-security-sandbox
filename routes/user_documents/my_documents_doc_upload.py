# routes/user_documents/my_documents_doc_upload.py
from flask import Blueprint, render_template, current_app, redirect, url_for
from flask_security import roles_accepted, current_user
from werkzeug.utils import secure_filename
from models import PDFDocument, DocumentRole, db
from forms import UploadDocumentForm
import os


my_documents_doc_upload_bp = Blueprint("my_documents_doc_upload", __name__)


@my_documents_doc_upload_bp.route("/upload_document", methods=["GET", "POST"])
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def upload_document():
    form = UploadDocumentForm()
    if form.validate_on_submit():
        f = form.document.data
        filename = secure_filename(f.filename)
        file_data = f.read()  # Read the file data

        # Save the file to the file system
        file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        f.save(file_path)

        # Create a new PDFDocument object
        document = PDFDocument(
            filename=filename,
            filepath=file_path,  # Save the file path to the new column
            user_id=current_user.id,
            size=len(file_data),  # Update the size to the length of the file data
            content_type=f.content_type,
            notes=form.notes.data,  # Save the notes to the new column
        )

        # Get the document role
        document_role_name = form.document_role.data
        document_role = DocumentRole.query.filter_by(name=document_role_name).first()

        # Add the document role to the document
        document.document_roles.append(document_role)

        # Add the document to the session and commit
        db.session.add(document)
        db.session.commit()

        return redirect(url_for("my_documents_view.mydocuments"))

    return render_template("documents/upload_document.html", form=form)
