# routes/auth/utils/verify_user_chosen_role_ids.py
import logging

def verify_user_chosen_role_ids(roles_dict, user_chosen_role_ids):
    matching_roles = {
        role_id: roles_dict[role_id]
        for role_id in user_chosen_role_ids
        if role_id in roles_dict
    }

    if not matching_roles:
        raise ValueError("unable to verify roles")

    logging.info(f"matching_roles looks like: {matching_roles}")
    return matching_roles