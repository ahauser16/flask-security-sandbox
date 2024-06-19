# forms/__init__.py
from .auth import (
    SignupForm,
    SigninForm,
    UserDetailsForm,
    SignupNotaryForm,
    SignupAdminForm,
    ConfirmRegistrationForm,
)

from .notary_log import NotarialActForm

from .user_documents import UploadDocumentForm, DeleteDocumentForm