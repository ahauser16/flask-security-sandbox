# forms/user_documents/document_delete_form.py
from flask_wtf import FlaskForm
from wtforms import SubmitField


class DeleteDocumentForm(FlaskForm):
    submit = SubmitField("Delete")
