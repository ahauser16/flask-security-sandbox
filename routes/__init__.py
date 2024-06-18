# routes/__init__.py
from .auth import auth_blueprints
from .notary_log import notary_log_blueprints
from .user_documents import user_documents_blueprints



all_blueprints = auth_blueprints + notary_log_blueprints + user_documents_blueprints
