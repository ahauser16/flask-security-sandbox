# routes/notary_log/resource_center_view.py
from flask import Blueprint, render_template

resource_center_view_bp = Blueprint("resource_center_view", __name__)


@resource_center_view_bp.route("/resourcecenter")
def resource_center_view():
    return render_template("resource_center/resource_center.html")
