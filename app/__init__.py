from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from app.config import Config  # Make sure this line is at the top
import os

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    CORS(app)
    jwt.init_app(app)
    
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.contacts import contacts_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(contacts_bp, url_prefix='/api/contacts')
    
    # Add root route
    @app.route('/')
    def index():
        return jsonify({
            "message": "Welcome to Contact Manager API",
            "endpoints": {
                "auth": "/api/auth",
                "contacts": "/api/contacts"
            }
        })
    
    return app