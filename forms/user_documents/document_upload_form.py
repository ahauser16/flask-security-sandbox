# forms/user_documents/document_upload_form.py

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired


class UploadDocumentForm(FlaskForm):
    document = FileField(
        "Document", validators=[FileRequired(), FileAllowed(["pdf"], "PDFs only!")]
    )
    document_role = SelectField(
        "Document Role",
        choices=[
            ("Admin", "Admin"),
            ("Principal", "Principal"),
            ("Traditional Notary", "Traditional Notary"),
            ("Electronic Notary", "Electronic Notary"),
        ],
        validators=[DataRequired()],
    )
    notes = TextAreaField("Notes")  # New field for notes
    submit = SubmitField("Upload")