# forms/__init__.py
from .auth import (
    SignupForm,
    SigninForm,
    UserDetailsForm,
    SignupNotaryForm,
    SignupAdminForm,
    ConfirmRegistrationForm,
    EmployerDetailsForm,
)

from .notary_log import NotarialActForm

from .user_documents import UploadDocumentForm, DeleteDocumentForm

# this syntax is unnecessary unless I want to import functions from the `utils` module outside of the `forms` module but currently this is not a part of my approach.
# from .utils import us_state_select_field
