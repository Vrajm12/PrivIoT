import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
migrate = Migrate()

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-priviot-secret-key-2025")

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize database migration
migrate.init_app(app, db)

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

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

# Import routes after app initialization to avoid circular imports
with app.app_context():
    # Import models and create tables
    import models
    
    # Create database tables first
    try:
        db.create_all()
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise
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
        try:
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
        except Exception as e:
            logger.error(f"Failed to create admin user: {str(e)}")
            db.session.rollback()

logger.info("PrivIoT application initialized successfully")
