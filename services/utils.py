import re


def is_valid_password(password):
    if len(password) < 8:
        return False

    if not re.search(r'[a-z]', password):
        return False

    if not re.search(r'[A-Z]', password):
        return False

    if not re.search(r'[0-9]', password):
        return False

    return True


def is_valid_phone_number(phone_number):
    if len(phone_number) == 9:
        return True

    if not re.search(r'[0-9]', phone_number):
        return False

    return False
