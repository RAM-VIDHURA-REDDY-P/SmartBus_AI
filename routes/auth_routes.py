
import re
import secrets
import hashlib
import hmac

from datetime import datetime, timedelta

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app
)

from flask_login import (
    login_user,
    logout_user,
    current_user,
    login_required
)

from flask_mail import Message
from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired
)

from extensions import db, mail
from models.user import User, PendingRegistration


auth = Blueprint("auth", __name__, url_prefix="/auth")


# ---------------------------------------
# EMAIL VALIDATION
# ---------------------------------------

def is_valid_gmail(email):

    pattern = r"^[a-zA-Z0-9._%+-]+@gmail\.com$"

    return bool(re.fullmatch(pattern, email.strip().lower()))


# ---------------------------------------
# PASSWORD VALIDATION
# ---------------------------------------

def is_strong_password(password):

    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[^A-Za-z0-9]", password)
    )


# ---------------------------------------
# TOKEN HASHING
# ---------------------------------------

def hash_token(token):

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


# ---------------------------------------
# SEND VERIFICATION EMAIL
# ---------------------------------------

def send_verification_email(pending, token):

    verification_link = url_for(
        "auth.verify_email",
        token=token,
        _external=True
    )

    message = Message(
        subject="SmartBus AI - Verify Your Email",
        recipients=[pending.email]
    )

    message.body = f"""
Hello {pending.full_name},

Thank you for registering with SmartBus AI.

To complete your registration, click the verification link below:

{verification_link}

This link expires in 24 hours.

If you did not request this registration, please ignore this email.

Regards,
SmartBus AI Team
"""

    mail.send(message)


# ---------------------------------------
# REGISTER
# ---------------------------------------

@auth.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":

        full_name = request.form.get(
            "full_name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        mobile_number = request.form.get(
            "mobile_number", ""
        ).strip()

        password = request.form.get("password", "")

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        role = request.form.get(
            "role", ""
        ).upper()

        if not all([
            full_name,
            email,
            mobile_number,
            password,
            confirm_password,
            role
        ]):

            flash("Please fill in all fields.", "danger")
            return redirect(url_for("auth.register"))

        if not is_valid_gmail(email):

            flash(
                "Only valid Gmail-format addresses ending in @gmail.com are accepted.",
                "danger"
            )

            return redirect(url_for("auth.register"))

        if not re.fullmatch(r"[0-9]{10,15}", mobile_number):

            flash(
                "Enter a valid mobile number containing 10 to 15 digits.",
                "danger"
            )

            return redirect(url_for("auth.register"))

        allowed_roles = [
            "PASSENGER",
            "DRIVER",
            "RESTAURANT"
        ]

        if role not in allowed_roles:

            flash("Invalid account role.", "danger")
            return redirect(url_for("auth.register"))

        if not is_strong_password(password):

            flash(
                "Password must contain at least 8 characters, "
                "one uppercase letter, one lowercase letter, "
                "one number and one special character.",
                "danger"
            )

            return redirect(url_for("auth.register"))

        if password != confirm_password:

            flash("Passwords do not match.", "danger")
            return redirect(url_for("auth.register"))

        existing_user = User.query.filter(
            (User.email == email) |
            (User.mobile_number == mobile_number)
        ).first()

        if existing_user:

            flash(
                "This email or mobile number is already registered.",
                "danger"
            )

            return redirect(url_for("auth.register"))

        existing_pending = PendingRegistration.query.filter(
            (PendingRegistration.email == email) |
            (PendingRegistration.mobile_number == mobile_number)
        ).first()

        if existing_pending:

            flash(
                "A registration is already pending for this email "
                "or mobile number. Please contact support to request "
                "another verification link.",
                "warning"
            )

            return redirect(url_for("auth.register"))

        # Generate a secure random verification token
        token = secrets.token_urlsafe(32)

        pending = PendingRegistration(
            full_name=full_name,
            email=email,
            mobile_number=mobile_number,
            role=role,
            password_hash=__import__(
                "werkzeug.security",
                fromlist=["generate_password_hash"]
            ).generate_password_hash(password),
            verification_token_hash=hash_token(token),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )

        try:

            db.session.add(pending)
            db.session.commit()

            # Send verification email
            send_verification_email(pending, token)

            flash(
                "A verification link has been sent to your Gmail. "
                "Complete email verification within 24 hours.",
                "success"
            )

            return redirect(url_for("auth.login"))

        except Exception:

            db.session.rollback()

            current_app.logger.exception(
                "Pending registration or verification email failed"
            )

            # Remove the pending record if it was saved
            failed_pending = PendingRegistration.query.filter_by(
                email=email
            ).first()

            if failed_pending:
                db.session.delete(failed_pending)
                db.session.commit()

            flash(
                "We could not send the verification email. "
                "Please check the email configuration and try again.",
                "danger"
            )

            return redirect(url_for("auth.register"))

    return render_template("auth/register.html")


# ---------------------------------------
# VERIFY EMAIL
# ---------------------------------------

@auth.route("/verify-email/<token>")
def verify_email(token):

    token_hash = hash_token(token)

    pending = PendingRegistration.query.filter_by(
        verification_token_hash=token_hash
    ).first()

    if not pending:

        flash(
            "Invalid or already used verification link.",
            "danger"
        )

        return redirect(url_for("auth.login"))

    if pending.expires_at < datetime.utcnow():

        db.session.delete(pending)
        db.session.commit()

        flash(
            "Your verification link has expired. "
            "Please register again.",
            "danger"
        )

        return redirect(url_for("auth.register"))

    existing_user = User.query.filter(
        (User.email == pending.email) |
        (User.mobile_number == pending.mobile_number)
    ).first()

    if existing_user:

        db.session.delete(pending)
        db.session.commit()

        flash(
            "An account with this email or mobile number already exists.",
            "warning"
        )

        return redirect(url_for("auth.login"))

    try:

        # Create the actual account only after email verification
        new_user = User(
            full_name=pending.full_name,
            email=pending.email,
            mobile_number=pending.mobile_number,
            password_hash=pending.password_hash,
            role=pending.role,
            is_active=True,
            is_email_verified=True
        )

        db.session.add(new_user)

        # Remove pending registration
        db.session.delete(pending)

        db.session.commit()

        flash(
            "Your email has been verified and your account "
            "has been created successfully. You can now log in.",
            "success"
        )

    except Exception:

        db.session.rollback()

        current_app.logger.exception(
            "Account creation after email verification failed"
        )

        flash(
            "Unable to complete registration. Please try again.",
            "danger"
        )

    return redirect(url_for("auth.login"))


# ---------------------------------------
# LOGIN
# ---------------------------------------

@auth.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get("password", "")

        if not email or not password:

            flash(
                "Please enter your email and password.",
                "danger"
            )

            return redirect(url_for("auth.login"))

        if not is_valid_gmail(email):

            flash(
                "Please enter a valid Gmail address.",
                "danger"
            )

            return redirect(url_for("auth.login"))

        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):

            flash("Invalid email or password.", "danger")
            return redirect(url_for("auth.login"))

        if not user.is_active:

            flash(
                "Your account is inactive. Contact support.",
                "danger"
            )

            return redirect(url_for("auth.login"))

        if not user.is_email_verified:

            flash(
                "Please verify your email before logging in.",
                "warning"
            )

            return redirect(url_for("auth.login"))

        login_user(user, remember=False, fresh=True)

        flash(
            f"Welcome, {user.full_name}!",
            "success"
        )

        if user.role == "PASSENGER":
            return redirect(
                url_for("dashboard.passenger_dashboard")
            )

        if user.role == "DRIVER":
            return redirect(
                url_for("dashboard.driver_dashboard")
            )

        if user.role == "RESTAURANT":
            return redirect(
                url_for("dashboard.restaurant_dashboard")
            )

        logout_user()

        flash("Invalid account role.", "danger")

        return redirect(url_for("auth.login"))

    return render_template("auth/login.html")


# ---------------------------------------
# LOGOUT
# ---------------------------------------

@auth.route("/logout", methods=["GET", "POST"])
@login_required
def logout():

    logout_user()

    flash(
        "You have logged out successfully.",
        "success"
    )

    return redirect(url_for("auth.login"))


# ---------------------------------------
# PASSWORD RESET TOKEN
# ---------------------------------------

def generate_reset_token(user):

    serializer = URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"]
    )

    token_data = {
        "user_id": user.id,
        "password_hash": user.password_hash
    }

    return serializer.dumps(
        token_data,
        salt="smartbus-password-reset"
    )


def verify_reset_token(token):

    serializer = URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"]
    )

    try:

        token_data = serializer.loads(
            token,
            salt="smartbus-password-reset",
            max_age=1800
        )

        user = db.session.get(
            User,
            token_data["user_id"]
        )

        if not user:
            return None

        if user.password_hash != token_data["password_hash"]:
            return None

        return user

    except (
        BadSignature,
        SignatureExpired,
        KeyError,
        TypeError
    ):
        return None


# ---------------------------------------
# FORGOT PASSWORD
# ---------------------------------------

@auth.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        if not is_valid_gmail(email):

            flash(
                "Please enter a valid Gmail address.",
                "danger"
            )

            return redirect(url_for("auth.forgot_password"))

        user = User.query.filter_by(email=email).first()

        if user and user.is_active and user.is_email_verified:

            try:

                token = generate_reset_token(user)

                reset_link = url_for(
                    "auth.reset_password",
                    token=token,
                    _external=True
                )

                message = Message(
                    subject="SmartBus AI - Password Reset",
                    recipients=[user.email]
                )

                message.body = f"""
Hello {user.full_name},

We received a request to reset your SmartBus AI password.

Click this link to reset your password:

{reset_link}

This link expires in 30 minutes.

If you did not request this, ignore this email.

Regards,
SmartBus AI Team
"""

                mail.send(message)

            except Exception:

                current_app.logger.exception(
                    "Password reset email could not be sent"
                )

        flash(
            "If a verified account exists with that email, "
            "a password reset link has been sent.",
            "info"
        )

        return redirect(url_for("auth.login"))

    return render_template("auth/forgot_password.html")


# ---------------------------------------
# RESET PASSWORD
# ---------------------------------------

@auth.route(
    "/reset-password/<token>",
    methods=["GET", "POST"]
)
def reset_password(token):

    if current_user.is_authenticated:
        logout_user()

    user = verify_reset_token(token)

    if not user:

        flash(
            "This password reset link is invalid or expired.",
            "danger"
        )

        return redirect(
            url_for("auth.forgot_password")
        )

    if request.method == "POST":

        password = request.form.get("password", "")

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not is_strong_password(password):

            flash(
                "Password must contain at least 8 characters, "
                "one uppercase letter, one lowercase letter, "
                "one number and one special character.",
                "danger"
            )

            return render_template(
                "auth/reset_password.html",
                token=token
            )

        if password != confirm_password:

            flash("Passwords do not match.", "danger")

            return render_template(
                "auth/reset_password.html",
                token=token
            )

        try:

            user.set_password(password)
            db.session.commit()

            flash(
                "Password changed successfully. Please log in.",
                "success"
            )

            return redirect(url_for("auth.login"))

        except Exception:

            db.session.rollback()

            current_app.logger.exception(
                "Password reset failed"
            )

            flash(
                "Unable to update your password. Please try again.",
                "danger"
            )

    return render_template(
        "auth/reset_password.html",
        token=token
    )
