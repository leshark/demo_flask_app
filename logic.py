from flask import request, render_template, jsonify, session, redirect, url_for
from webargs import flaskparser

from csrf import generate_csrf_token
from models import db, User
from validators import require_csrf_token, FORM_ARGS


def index():
    if session.get('logged_in'):
        return redirect("https://yandex.ru")
    return render_template("start.html", csrf_token=generate_csrf_token)


@require_csrf_token
def pre_sign_in():
    resp = request.json

    login = resp.get("l")
    password = resp.get("p")

    user = User.query.filter_by(login=login).first()
    if user is not None and user.has_correct_password(password):
        session["logged_in"] = True
        return jsonify({"message": "You have logged in successfully", "status": 0})
    else:
        return jsonify({"message": "Wrong username or password. Try again", "status": 1})


def sign_in():
    # process user here
    return redirect(url_for("index"))


@require_csrf_token
def register():
    parsed_args = flaskparser.parser.parse(FORM_ARGS, request, location="json")

    full_name = parsed_args.get("f")
    login = parsed_args.get("l")
    password = parsed_args.get("p")

    if User.query.filter_by(login=login).first() is not None:
        # ideally we should send email message to verify account, as stated here:
        # https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#account-creation
        return jsonify({"message": "Registration failed, please try again", "status": 1})

    reg = User(full_name=full_name, login=login, password=password)
    db.session.add(reg)
    db.session.commit()

    return jsonify({"message": "You have successfully registered", "status": 0})


def handle_unprocessable_entity(err):
    return jsonify({
        'status': 1,
        'message': "Invalid symbols in login/full_name or incorrect fields length"
    })
