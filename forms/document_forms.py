from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField, SelectField
from wtforms.validators import DataRequired

class UploadDocumentForm(FlaskForm):
    document = FileField('Document', validators=[
        FileRequired(),
        FileAllowed(['pdf'], 'PDFs only!')
    ])
    document_role = SelectField(
        'Document Role',
        choices=[
            ('Admin', 'Admin'),
            ('Principal', 'Principal'),
            ('Traditional Notary', 'Traditional Notary'),
            ('Electronic Notary', 'Electronic Notary')
        ],
        validators=[DataRequired()]
    )
    submit = SubmitField('Upload')