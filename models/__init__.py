# __init__.py
from models.database import (
    db,
    roles_users,
    document_role_documents,
    document_role_users,
)


from .user import User
from .role import Role
from .document_role import DocumentRole
from .user_details import UserDetails
from .employer_details import EmployerDetails
from .pdf_document import PDFDocument
from .notary_credentials import NotaryCredentials
from .notarial_act import NotarialAct

__all__ = [
    "User",
    "Role",
    "DocumentRole",
    "UserDetails",
    "EmployerDetails",
    "PDFDocument",
    "NotaryCredentials",
    "NotarialAct",
    "roles_users",
    "document_role_users",
    "document_role_documents",
    "db",
]
