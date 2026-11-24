import os
from flask import Flask
from backend.routes import backend_bp
from frontend.routes import frontend_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", "dev-qualys-triage-secret-key-2026")
    app.register_blueprint(frontend_bp)
    app.register_blueprint(backend_bp)
    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
