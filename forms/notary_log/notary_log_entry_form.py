# notary_log_forms.py
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    IntegerField,
    SelectField,
    SubmitField,
    DateField,
    TimeField,
    HiddenField,
    DateTimeField,
)
from wtforms.validators import DataRequired
from datetime import datetime
import pytz


class NotarialActForm(FlaskForm):
    # the default property of the DateTimeField function controls how the form displays time which is currently set to UTC syntax.  
    date_time = DateTimeField("Date Time", validators=[DataRequired()], default=datetime.utcnow)
    act_type = SelectField(
        "Notarial Act Type",
        choices=[
            (
                "Administering Oaths and Affirmations",
                "Taking sworn statements under oath.",
            ),
            (
                "Taking Affidavits and Depositions",
                "Taking written statements confirmed by oath or affirmation for use as evidence.",
            ),
            (
                "Taking Acknowledgments",
                "Confirming that signatures on documents are genuine and were made voluntarily.",
            ),
            (
                "Certifying Copies of Documents",
                "Attesting that copies of documents are true and accurate reproductions of the original.",
            ),
            (
                "Protesting Non-Payment of Bills",
                "Noting and certifying dishonor of negotiable instruments such as checks or promissory notes.",
            ),
            (
                "Executing Jurats",
                "Certifying that a document signer personally appeared before the notary, was identified by the notary, and signed the document in the presence of the notary.",
            ),
            (
                "Witnessing Signatures",
                "Acting as a witness to the signing of documents.",
            ),
            (
                "Electronic Notarization",
                "Performing notarial acts electronically using approved communication technology.",
            ),
            (
                "Certifying the Authenticity of Signatures",
                "Attesting to the validity of signatures on documents.",
            ),
        ],
        validators=[DataRequired()],
    )
    principal_name = StringField(
        "Principal Name",
        validators=[DataRequired()],
        default="Holdoor Smith",
    )
    principal_addressLine1 = StringField(
        "Address Line 1",
        validators=[DataRequired()],
        default="123 Main St.",
    )
    principal_addressLine2 = StringField(
        "Address Line 2",
        validators=[],
        default="apartment 2B",
    )
    principal_city = StringField(
        "City",
        validators=[DataRequired()],
        default="Brooklyn",
    )
    principal_state = SelectField(
        "State",
        choices=[
            ("AL", "Alabama"),
            ("AK", "Alaska"),
            ("AZ", "Arizona"),
            ("AR", "Arkansas"),
            ("CA", "California"),
            ("CO", "Colorado"),
            ("CT", "Connecticut"),
            ("DE", "Delaware"),
            ("FL", "Florida"),
            ("GA", "Georgia"),
            ("HI", "Hawaii"),
            ("ID", "Idaho"),
            ("IL", "Illinois"),
            ("IN", "Indiana"),
            ("IA", "Iowa"),
            ("KS", "Kansas"),
            ("KY", "Kentucky"),
            ("LA", "Louisiana"),
            ("ME", "Maine"),
            ("MD", "Maryland"),
            ("MA", "Massachusetts"),
            ("MI", "Michigan"),
            ("MN", "Minnesota"),
            ("MS", "Mississippi"),
            ("MO", "Missouri"),
            ("MT", "Montana"),
            ("NE", "Nebraska"),
            ("NV", "Nevada"),
            ("NH", "New Hampshire"),
            ("NJ", "New Jersey"),
            ("NM", "New Mexico"),
            ("NY", "New York"),
            ("NC", "North Carolina"),
            ("ND", "North Dakota"),
            ("OH", "Ohio"),
            ("OK", "Oklahoma"),
            ("OR", "Oregon"),
            ("PA", "Pennsylvania"),
            ("RI", "Rhode Island"),
            ("SC", "South Carolina"),
            ("SD", "South Dakota"),
            ("TN", "Tennessee"),
            ("TX", "Texas"),
            ("UT", "Utah"),
            ("VT", "Vermont"),
            ("VA", "Virginia"),
            ("WA", "Washington"),
            ("WV", "West Virginia"),
            ("WI", "Wisconsin"),
            ("WY", "Wyoming"),
        ],
        validators=[DataRequired()],
    )
    principal_zipCode = StringField(
        "Zip Code",
        validators=[DataRequired()],
        default="12345",
    )
    service_number = IntegerField(
        "Number of Services",
        validators=[DataRequired()],
        default="1",
    )
    service_type = SelectField(
        "Notarial Service Type",
        choices=[
            (
                "Providing Notarial Acts",
                "Performing the specific notarial acts listed above.",
            ),
            ("Maintaining Records", "Keeping records of all notarial acts performed."),
            (
                "Educating Clients",
                "Informing clients about the requirements and processes for notarial acts.",
            ),
            (
                "Verifying Identity",
                "Confirming the identity of individuals requesting notarial acts through acceptable forms of identification.",
            ),
            (
                "Providing Legal Disclaimers",
                "Clarifying that notaries are not attorneys and cannot provide legal advice unless they are also licensed attorneys.",
            ),
            (
                "Handling Electronic Records",
                "Managing electronic records and maintaining the security and integrity of electronic notarizations.",
            ),
            (
                "Certifying Official Character",
                "Notaries can have their official character certified by the Secretary of State or county clerks.",
            ),
        ],
        validators=[DataRequired()],
    )
    principal_credential_type = SelectField(
        "Principal Credential Type",
        choices=[
            (
                "Government-Issued Photo ID - Driver's license",
                "Government-Issued Photo ID - Driver's license",
            ),
            (
                "Government-Issued Photo ID - Passport",
                "Government-Issued Photo ID - Passport",
            ),
            (
                "Government-Issued Photo ID - State ID card",
                "Government-Issued Photo ID - State ID card",
            ),
            (
                "Government-Issued Photo ID - Military ID",
                "Government-Issued Photo ID - Military ID",
            ),
            (
                "Other Acceptable Form of ID - Permanent Resident Card (Green Card)",
                "Other Acceptable Form of ID - Permanent Resident Card (Green Card)",
            ),
            (
                "Other Acceptable Form of ID - Foreign Passport (with or without a U.S. visa)",
                "Other Acceptable Form of ID - Foreign Passport (with or without a U.S. visa)",
            ),
            (
                "Other Acceptable Form of ID - National ID card (if it includes a photo and signature)",
                "Other Acceptable Form of ID - National ID card (if it includes a photo and signature)",
            ),
            (
                "Additional Method - Personal Knowledge: The notary personally knows the principal and can attest to their identity without requiring additional documentation.",
                "Additional Method - Personal Knowledge: The notary personally knows the principal and can attest to their identity without requiring additional documentation.",
            ),
            (
                "Credible Witness: A credible witness who knows both the notary and the principal can vouch for the principal's identity, provided the witness has proper identification.",
                "Credible Witness: A credible witness who knows both the notary and the principal can vouch for the principal's identity, provided the witness has proper identification.",
            ),
            (
                "Electronic Identification - Credential Analysis: Utilizing technology to confirm the authenticity of an ID presented electronically.",
                "Electronic Identification - Credential Analysis: Utilizing technology to confirm the authenticity of an ID presented electronically.",
            ),
            (
                "Electronic Identification - Identity Proofing: Using knowledge-based authentication (KBA) questions or other methods approved by the Secretary of State.",
                "Electronic Identification - Identity Proofing: Using knowledge-based authentication (KBA) questions or other methods approved by the Secretary of State.",
            ),
        ],
        validators=[DataRequired()],
    )
    communication_tech = SelectField(
        "Communication Tech",
        choices=[
            (
                "Google Meet",
                "Google Meet",
            ),
            (
                "Zoom",
                "Zoom",
            ),
            ("N/A", "N/A"),
        ],
        validators=[DataRequired()],
    )
    certification_authority = SelectField(
        "Certification Authority",
        choices=[
            (
                "Stripe",
                "Stripe",
            ),
            (
                "ID.ME",
                "ID.ME",
            ),
            ("N/A", "N/A"),
        ],
        validators=[DataRequired()],
    )
    verification_provider = SelectField(
        "Verification Provider",
        choices=[
            (
                "Stripe",
                "Stripe",
            ),
            (
                "ID.ME",
                "ID.ME",
            ),
            ("N/A", "N/A"),
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("Submit")

