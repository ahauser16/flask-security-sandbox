import logging
from datetime import datetime
import urllib.parse
import requests
from flask import session


def match_notary_credentials(form_data):
    email = form_data.get("email")
    password = form_data.get("password")
    full_name = form_data.get("full_name")
    commission_id = form_data.get("commission_id")
    commissioned_county = form_data.get("commissioned_county")
    commission_start_date_str = form_data.get("commission_start_date")
    commission_expiration_date_str = form_data.get("commission_expiration_date")

    commission_start_date = datetime.strptime(commission_start_date_str, "%Y-%m-%d")
    commission_expiration_date = datetime.strptime(
        commission_expiration_date_str, "%Y-%m-%d"
    )

    role_mapping = {3: "Traditional", 4: "Electronic"}
    role_value = int(session.get("role_id", 0))
    commission_type = role_mapping.get(role_value)

    commission_id_encoded = urllib.parse.quote_plus(str(commission_id))

    response = requests.get(
        "https://data.ny.gov/resource/rwbv-mz6z.json",
        params={
            "commission_holder_name": full_name,
            "commission_number_uid": commission_id_encoded,
            "commissioned_county": commissioned_county,
            "commission_type_traditional_or_electronic": commission_type,
            "term_issue_date": commission_start_date_str,
            "term_expiration_date": commission_expiration_date_str,
        },
    )
    data = response.json()

    if not data or not isinstance(data, list) or len(data) == 0:
        return None

    api_data = data[0]
    if (
        api_data["commission_holder_name"].lower() == full_name.lower()
        and api_data["commissioned_county"].lower() == commissioned_county.lower()
        and datetime.strptime(api_data["term_issue_date"], "%Y-%m-%dT%H:%M:%S.%f")
        == commission_start_date
        and datetime.strptime(api_data["term_expiration_date"], "%Y-%m-%dT%H:%M:%S.%f")
        == commission_expiration_date
    ):
        logging.info("API data matches user data.")
        return api_data
    else:
        logging.info("API data does not match user data.")
        return None
