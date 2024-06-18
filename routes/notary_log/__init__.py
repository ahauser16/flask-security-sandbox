# routes/notary_log/__init__.py
from .notary_log_view import notary_log_view_bp
from .notary_log_entry_create import notary_log_entry_create_bp
from .notary_log_entry_read import notary_log_entry_read_bp  
from .notary_log_entry_update import notary_log_entry_update_bp
from .notary_log_entry_delete import notary_log_entry_delete_bp
from .notary_log_get_table_data import notary_log_get_table_data_bp  



notary_log_blueprints = [
    notary_log_view_bp,
    notary_log_entry_create_bp,
    notary_log_entry_read_bp,
    notary_log_entry_update_bp,
    notary_log_entry_delete_bp,
    notary_log_get_table_data_bp,  
]  
