# routes/__init__.py
from .auth import auth_blueprints
from .notary_log import notary_log_blueprints
from .user_documents import user_documents_blueprints
from .resource_center import resource_center_blueprints
from .find_notary import find_notary_blueprints
from .user_profile import user_profile_blueprints
from .e_signature import e_signature_blueprints
from .errors import error_blueprints


all_blueprints = (
    auth_blueprints
    + notary_log_blueprints
    + user_documents_blueprints
    + resource_center_blueprints
    + find_notary_blueprints
    + user_profile_blueprints
    + e_signature_blueprints
    + error_blueprints
)
