# notary_auth.py
import logging
from datetime import datetime
import urllib.parse
import requests

API_URL = "https://data.ny.gov/resource/rwbv-mz6z.json"

# This function `parse_date` takes a date string and a format string as arguments. It tries to convert the date string into a `datetime` object using the format string. If the conversion fails (because the date string is not in the expected format), it logs an error message and returns `None`.
def parse_date(date_str, format="%Y-%m-%d"):
    try:
        return datetime.strptime(date_str, format)
    except ValueError:
        logging.error(f"Invalid date: {date_str}")
        return None

# This function `match_notary_credentials` takes a dictionary notary_form_data as an argument. It extracts several values from this dictionary and stores them in local variables.
def match_notary_credentials(notary_form_data):
    full_name = notary_form_data.get("full_name")
    commission_id = notary_form_data.get("commission_id")
    commissioned_county = notary_form_data.get("commissioned_county")
    commission_start_date_str = notary_form_data.get("commission_start_date")
    commission_expiration_date_str = notary_form_data.get("commission_expiration_date")

    #These lines convert the start and expiration date strings into datetime objects.
    commission_start_date = parse_date(commission_start_date_str)
    commission_expiration_date = parse_date(commission_expiration_date_str)

    #This line URL-encodes the commission ID. This is necessary because URLs can only contain certain characters.
    commission_id_encoded = urllib.parse.quote_plus(str(commission_id))

    # Convert the start and expiration date strings into the format expected by the API.
    commission_start_date_formatted = f"{commission_start_date_str}T00:00:00.000"
    commission_expiration_date_formatted = f"{commission_expiration_date_str}T00:00:00.000"

    # These lines send a GET request to the API. The parameters of the request are provided as a dictionary. If the request fails for any reason, an error message is logged and the function returns None.
    try:
        response = requests.get(
            API_URL,
            params={
                "commission_holder_name": full_name,
                "commission_number_uid": commission_id_encoded,
                "commissioned_county": commissioned_county,
                "term_issue_date": commission_start_date_formatted,
                "term_expiration_date": commission_expiration_date_formatted,
            },
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None

    # This line converts the response from the API into a Python data structure (a list or a dictionary).
    data = response.json()

    # These lines check if the response from the API is empty or not a list. If it is, the function returns None. Otherwise, it extracts the first item from the list and stores it in the variable `api_data`.
    if not data or not isinstance(data, list) or len(data) == 0:
        return None

    # This line gets the first item from the list.
    api_data = data[0]
    
    # These lines check if the data from the API matches the data from the form. The checks are case-insensitive and the dates are compared as datetime objects. If the data matches, the function returns a dictionary with the relevant information. Otherwise, it returns None.
    if (
        api_data["commission_holder_name"].lower() == full_name.lower()
        and api_data["commissioned_county"].lower() == commissioned_county.lower()
        and parse_date(api_data["term_issue_date"], "%Y-%m-%dT%H:%M:%S.%f")
        == commission_start_date
        and parse_date(api_data["term_expiration_date"], "%Y-%m-%dT%H:%M:%S.%f")
        == commission_expiration_date
    ):
        logging.info("API data matches user data.")
        notary_cred_api_resp = {
            "commission_holder_name": api_data["commission_holder_name"],
            "commission_number_uid": api_data["commission_number_uid"],
            "commissioned_county": api_data["commissioned_county"],
            "commission_type_traditional_or_electronic": api_data[
                "commission_type_traditional_or_electronic"
            ],
            "term_issue_date": parse_date(
                api_data["term_issue_date"], "%Y-%m-%dT%H:%M:%S.%f"
            ),
            "term_expiration_date": parse_date(
                api_data["term_expiration_date"], "%Y-%m-%dT%H:%M:%S.%f"
            ),
        }
        return notary_cred_api_resp
    else:
        logging.info("API data does not match user data.")
        return None
