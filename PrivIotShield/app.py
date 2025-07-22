import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
from flask_wtf.csrf import CSRFProtect


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-priviot-secret-key-2025")

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Configure CSRF exemptions for API endpoints that use token authentication
# In a production environment, we would use a more secure method for API authentication
# such as JWT tokens or OAuth2
@csrf.exempt
def csrf_exempt(view):
    return view

# Configure the database
try:
    # First try to connect to PostgreSQL if DATABASE_URL is provided
    if os.environ.get("DATABASE_URL") and 'postgresql' in os.environ.get("DATABASE_URL", ""):
        # Test connection to PostgreSQL
        import psycopg2
        conn_params = os.environ.get("DATABASE_URL")
        try:
            conn = psycopg2.connect(conn_params)
            conn.close()
            # If connection successful, use PostgreSQL
            app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
            app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
                "pool_recycle": 300,
                "pool_pre_ping": True,
            }
            logger.info("Using PostgreSQL database")
        except Exception as e:
            logger.warning(f"Failed to connect to PostgreSQL: {str(e)}. Falling back to SQLite.")
            # Use SQLite as fallback if PostgreSQL connection fails
            app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///priviot.db"
            logger.info("Using SQLite database")
    else:
        # Use SQLite as a fallback if no DATABASE_URL
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///priviot.db"
        logger.info("Using SQLite database")
except Exception as e:
    # Use SQLite as fallback if there's any exception
    logger.error(f"Error configuring database: {str(e)}. Using SQLite as fallback.")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///priviot.db"
    logger.info("Using SQLite database")
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
