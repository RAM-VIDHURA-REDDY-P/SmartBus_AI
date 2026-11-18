
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db


class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    full_name = db.Column(db.String(100), nullable=False)

    email = db.Column(db.String(120), unique=True, nullable=False)

    mobile_number = db.Column(db.String(15), unique=True, nullable=False)

    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(
        db.Enum("PASSENGER", "DRIVER", "RESTAURANT"),
        nullable=False
    )

    is_active = db.Column(db.Boolean, default=True, nullable=False)

    is_email_verified = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.email}>"


# ---------------------------------------
# PENDING REGISTRATION MODEL
# ---------------------------------------

class PendingRegistration(db.Model):

    __tablename__ = "pending_registrations"

    id = db.Column(db.Integer, primary_key=True)

    full_name = db.Column(db.String(100), nullable=False)

    email = db.Column(db.String(120), unique=True, nullable=False)

    mobile_number = db.Column(db.String(15), unique=True, nullable=False)

    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(
        db.Enum("PASSENGER", "DRIVER", "RESTAURANT"),
        nullable=False
    )

    verification_token_hash = db.Column(
        db.String(64),
        unique=True,
        nullable=False
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.current_timestamp()
    )

    def __repr__(self):
        return f"<PendingRegistration {self.email}>"
