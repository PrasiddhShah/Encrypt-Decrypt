# __init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from flask_migrate import Migrate
from .config import config  # Import the config dictionary
import os

db = SQLAlchemy()
login_manager = LoginManager()
oauth = OAuth()
migrate = Migrate()

def create_app(config_name=None):
    app = Flask(__name__)

    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'default')

    app.config.from_object(config[config_name])

    db.init_app(app)
    login_manager.init_app(app)
    oauth.init_app(app)
    migrate.init_app(app, db)

    # Configure CORS to allow requests from Angular frontend
    CORS(
        app,
        resources={
            r"/api/*": {"origins": "http://localhost:4200"},
            r"/auth/*": {"origins": "http://localhost:4200"}
        },
        supports_credentials=True
    )

    # Register Blueprints
    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from app.crypto import crypto as crypto_blueprint
    app.register_blueprint(crypto_blueprint, url_prefix='/api')

    # Import models to ensure they are registered with SQLAlchemy
    with app.app_context():
        from . import models

    return app
