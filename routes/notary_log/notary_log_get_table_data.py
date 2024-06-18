# routes/notary_log/notarial_act_table_data.py
from flask import Blueprint, request
from flask_security import current_user
from models import NotarialAct, db
import logging
from sqlalchemy import cast, String

notary_log_get_table_data_bp = Blueprint("notarial_act_table_data", __name__)


@notary_log_get_table_data_bp.route("/notarial_act_table_data")
def get_notarial_act_table_data():

    # Get the current user's ID
    current_user_id = current_user.id

    # Filter the NotarialAct records by the current user's ID
    query = NotarialAct.query.filter_by(user_id=current_user_id)

    # search filter
    search = request.args.get("search")
    logging.info(f"Received search parameter: {search}")
    if search:
        query = query.filter(
            db.or_(
                cast(NotarialAct.date_time, String).like(f"%{search}%"),
                NotarialAct.act_type.like(f"%{search}%"),
                NotarialAct.principal_name.like(f"%{search}%"),
                NotarialAct.principal_addressLine1.like(f"%{search}%"),
                NotarialAct.principal_addressLine2.like(f"%{search}%"),
                NotarialAct.principal_city.like(f"%{search}%"),
                NotarialAct.principal_state.like(f"%{search}%"),
                NotarialAct.principal_zipCode.like(f"%{search}%"),
                cast(NotarialAct.service_number, String).like(f"%{search}%"),
                NotarialAct.service_type.like(f"%{search}%"),
                NotarialAct.principal_credential_type.like(f"%{search}%"),
                NotarialAct.communication_tech.like(f"%{search}%"),
                NotarialAct.certification_authority.like(f"%{search}%"),
                NotarialAct.verification_provider.like(f"%{search}%"),
            )
        )
    total = query.count()
    logging.info(f"Total records before sorting and pagination: {total}")

    # sorting
    sort = request.args.get("sort")
    logging.info(f"Received sort parameters: {sort}")
    if sort:
        order = []
        for s in sort.split(","):
            direction = s[0]
            name = s[1:]
            logging.info(
                f"Processing sort parameter: {s}, direction: {direction}, name: {name}"
            )
            if name not in [
                "date_time",
                "act_type",
                "principal_name",
                "principal_addressLine1",
                "principal_addressLine2",
                "principal_city",
                "principal_state",
                "principal_zipCode",
                "service_number",
                "service_type",
                "principal_credential_type",
                "communication_tech",
                "certification_authority",
                "verification_provider",
            ]:
                return {"error": "Invalid column name for sorting: " + name}, 400
            col = getattr(NotarialAct, name)
            if direction == "-":
                col = col.desc()
            order.append(col)
        logging.info(f"Generated order: {order}")
        if order:
            query = query.order_by(*order)

    # pagination
    start = request.args.get("start", type=int, default=-1)
    length = request.args.get("length", type=int, default=-1)
    logging.info(f"Received pagination parameters: start={start}, length={length}")
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    data = [act.to_dict() for act in query]
    logging.info(f"Returning {len(data)} records")
    return {
        "data": data,
        "total": total,
    }
