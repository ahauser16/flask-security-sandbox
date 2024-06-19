# routes/find_notary/find_notary_view.py
from flask import Blueprint, render_template

find_notary_view_bp = Blueprint("find_notary_view", __name__)


@find_notary_view_bp.route("/findnotary")
def find_notary_view():
    return render_template("find_notary/find_notary.html")
