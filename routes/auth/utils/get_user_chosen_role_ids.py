# routes/auth/utils/get_user_chosen_role_ids.py
import logging


def get_user_chosen_role_ids(session):
    user_chosen_role_ids = session.get("signup_form_data", {}).get("role_ids", [])
    logging.info(f"user_chosen_role_ids looks like: {user_chosen_role_ids}")
    return user_chosen_role_ids
