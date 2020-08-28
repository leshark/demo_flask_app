import functools

from flask import request, jsonify
from webargs import fields, validate

from csrf import validate_csrf_token


def require_csrf_token(func):
    @functools.wraps(func)
    def wrapper_decorator(*args, **kwargs):
        csrf_token = request.headers.get("X-CSRFToken")
        if not validate_csrf_token(csrf_token):
            return jsonify({"message": "CSRF token error", "status": 1})

        value = func(*args, **kwargs)
        return value

    return wrapper_decorator


def validate_field(text):
    """xss prevention"""
    return not any(symbol in text for symbol in [">", "<", "&", "'", "\""])


FORM_ARGS = {
    'f': fields.Str(required=True, validate=[validate.Length(min=1, max=120), validate_field]),
    'l': fields.Str(required=True, validate=[validate.Length(min=8, max=64), validate_field]),
    'p': fields.Str(required=True, validate=[validate.Length(min=8, max=64)])
}
