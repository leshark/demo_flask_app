from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.hybrid import hybrid_property
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), unique=True)
    login = db.Column(db.String(64), unique=True)
    _password = db.Column(db.String(64))

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, plaintext):
        # werkzeug.security generates salt automatically
        self._password = generate_password_hash(plaintext)

    def has_correct_password(self, plaintext):
        return check_password_hash(self._password, plaintext)
