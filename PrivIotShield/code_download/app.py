import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager
from werkzeug.security import generate_password_hash


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///priviot.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Configure OpenAI API key
app.config["OPENAI_API_KEY"] = os.environ.get("OPENAI_API_KEY")

# Configure Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize the app with the extension
db.init_app(app)

# Import routes after app initialization to avoid circular imports
with app.app_context():
    # Import models and create tables
    import models
    
    # Create database tables first
    db.create_all()
    logger.info("Database tables created successfully")
    
    # Now import routes after tables are created
    from routes import *
    from api import api_bp
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Create admin user if it doesn't exist
    from models import User
    admin_exists = User.query.filter_by(username='admin').first()
    if not admin_exists:
        admin_password = os.environ.get("ADMIN_PASSWORD", "PrivIoTAdmin123!")
        admin = User(
            username='admin',
            email='admin@priviot.io',
            password_hash=generate_password_hash(admin_password),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()
        logger.info("Admin user created successfully")

logger.info("PrivIoT application initialized successfully")
