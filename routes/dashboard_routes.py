
from flask import Blueprint, render_template
from flask_login import login_required, current_user

dashboard = Blueprint("dashboard", __name__)


# Common dashboard redirect
@dashboard.route("/dashboard")
@login_required
def home():

    if current_user.role == "PASSENGER":
        return passenger_dashboard()

    elif current_user.role == "DRIVER":
        return driver_dashboard()

    elif current_user.role == "RESTAURANT":
        return restaurant_dashboard()

    return "Invalid user role", 403


# Passenger dashboard
@dashboard.route("/passenger/dashboard")
@login_required
def passenger_dashboard():

    if current_user.role != "PASSENGER":
        return "Access denied", 403

    return render_template(
        "passenger/dashboard.html",
        user=current_user
    )


# Driver dashboard
@dashboard.route("/driver/dashboard")
@login_required
def driver_dashboard():

    if current_user.role != "DRIVER":
        return "Access denied", 403

    return render_template(
        "driver/dashboard.html",
        user=current_user
    )


# Restaurant owner dashboard
@dashboard.route("/restaurant/dashboard")
@login_required
def restaurant_dashboard():

    if current_user.role != "RESTAURANT":
        return "Access denied", 403

    return render_template(
        "restaurant/dashboard.html",
        user=current_user
    )
