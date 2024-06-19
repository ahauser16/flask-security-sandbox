# routes/e_signature/my_e_signature_view.py

from flask import Blueprint, render_template
from flask_security import roles_accepted

my_e_signature_view_bp = Blueprint("my_e_signature_view", __name__)


@my_e_signature_view_bp.route("/myesignature")
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def my_e_signature_view():
    return render_template("e_signature/my_e_signature.html")
