import os

from flask import Flask

from logic import index, register, pre_sign_in, sign_in, handle_unprocessable_entity
from models import db


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ["SECRET_KEY"].encode()
    app.config["field_name"] = "csrf-token"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///example.sqlite"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    with app.app_context():
        db.create_all()

    app.add_url_rule('/', 'index', index)
    app.add_url_rule('/reg', 'register', register, methods=["POST"])
    app.add_url_rule("/pre_signin", "presign_in", pre_sign_in, methods=["POST"])
    app.add_url_rule("/signin", "sign_in", sign_in, methods=["POST"])
    app.register_error_handler(422, handle_unprocessable_entity)
    return app


if __name__ == '__main__':
    create_app().run()
