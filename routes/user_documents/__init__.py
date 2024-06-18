# routes/user_documents/__init__.py
from .my_documents_view import my_documents_view_bp
from .my_documents_doc_upload import my_documents_doc_upload_bp
from .my_documents_doc_download import my_documents_doc_download_bp
from .my_documents_doc_delete import my_documents_doc_delete_bp
from .my_documents_doc_view import my_documents_doc_view_bp

user_documents_blueprints = [
    my_documents_view_bp,
    my_documents_doc_upload_bp,
    my_documents_doc_download_bp,
    my_documents_doc_delete_bp,
    my_documents_doc_view_bp,
]
