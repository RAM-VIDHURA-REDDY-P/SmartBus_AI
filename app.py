
from flask import Flask, jsonify, render_template
from sqlalchemy import text
from flask_wtf.csrf import CSRFProtect

from config import Config
from extensions import db, login_manager, mail


def create_app():

    app = Flask(__name__)

    # Load application configuration
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    csrf = CSRFProtect(app)

    # Import database models
    from models.user import User

    # Load logged-in user
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Import application routes
    from routes.auth_routes import auth
    from routes.dashboard_routes import dashboard

    # Register blueprints
    app.register_blueprint(auth)
    app.register_blueprint(dashboard)

    # Home page
    @app.route("/")
    def home():
        return render_template("index.html")

    # Database connection health check
    @app.route("/health/db")
    def database_health():

        try:
            with db.engine.connect() as connection:
                connection.execute(text("SELECT 1"))

            return jsonify({
                "status": "success",
                "message": "MySQL connection successful!"
            })

        except Exception:
            app.logger.exception("Database connection failed")

            return jsonify({
                "status": "error",
                "message": "Database connection failed"
            }), 500

    # Prevent sensitive pages from being cached
    @app.after_request
    def prevent_page_caching(response):

        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, private"
        )

        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        return response

    return app


# Run application
if __name__ == "__main__":

    app = create_app()

    with app.app_context():
        db.create_all()
        print("SmartBus AI database is ready!")

    app.run(debug=True)
