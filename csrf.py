import hashlib
import os

from flask import current_app, session
from itsdangerous import BadData, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import safe_str_cmp


def generate_csrf_token():
    """Csrf token per session realisation"""
    s = URLSafeTimedSerializer(current_app.secret_key, salt='custom-csrf-token')
    field_name = current_app.config.get("field_name")

    if field_name not in session:
        session[field_name] = hashlib.sha1(os.urandom(64)).hexdigest()

    try:
        token = s.dumps(session[field_name])
    except TypeError:
        session[field_name] = hashlib.sha1(os.urandom(64)).hexdigest()
        token = s.dumps(session[field_name])

    return token


def validate_csrf_token(data, time_limit=None):
    field_name = current_app.config.get("field_name")

    if not data:
        # 'The CSRF token is missing.'
        return False

    if field_name not in session:
        # 'The CSRF session token is missing.'
        return False

    s = URLSafeTimedSerializer(current_app.secret_key, salt='custom-csrf-token')

    try:
        token = s.loads(data, max_age=time_limit)
    except SignatureExpired:
        # 'The CSRF token has expired.'
        return False
    except BadData:
        # 'The CSRF token is invalid.'
        return False

    # safe comparision to escape timing attack
    if not safe_str_cmp(session[field_name], token):
        # 'The CSRF tokens do not match.'
        return False

    return True
