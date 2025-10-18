import os
import logging
from flask import Flask, render_template
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash
from extensions import db, login_manager

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

migrate = Migrate()

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-priviot-secret-key-2025")

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Temporarily disable CSRF for testing (REMOVE IN PRODUCTION)
app.config['WTF_CSRF_ENABLED'] = False

# Initialize database migration
migrate.init_app(app, db)

# Configure the database
try:
    if os.environ.get("DATABASE_URL") and 'postgresql' in os.environ.get("DATABASE_URL", ""):
        import psycopg2
        conn_params = os.environ.get("DATABASE_URL")
        try:
            conn = psycopg2.connect(conn_params)
            conn.close()
            app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
            app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
                "pool_recycle": 300,
                "pool_pre_ping": True,
            }
            logger.info("Using PostgreSQL database")
        except Exception as e:
            logger.warning(f"Failed to connect to PostgreSQL: {str(e)}. Falling back to SQLite.")
            app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///priviot.db"
            logger.info("Using SQLite database")
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///priviot.db"
        logger.info("Using SQLite database")
except Exception as e:
    logger.error(f"Error configuring database: {str(e)}. Using SQLite as fallback.")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///priviot.db"
    logger.info("Using SQLite database")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["OPENAI_API_KEY"] = os.environ.get("OPENAI_API_KEY")

# Configure Login Manager
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

# Import and initialize routes after app is created
try:
    import routes
    routes.init_routes(app, csrf)  # Initialize routes with app and csrf instances
    logger.info("Routes imported and initialized successfully")
except ImportError as e:
    logger.warning(f"routes module not found: {str(e)}, skipping route imports")

# Register API blueprint
try:
    from api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    logger.info("API blueprint registered successfully")
except ImportError as e:
    logger.warning(f"api module not found: {str(e)}, skipping API blueprint registration")

# Initialize database and create admin user
with app.app_context():
    # Import models INSIDE app context
    from models import User, Device, Scan, Vulnerability, PrivacyIssue, Report, UserActivity, DeviceGroup
    
    # Create database tables first
    try:
        db.create_all()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
    
    # Create admin user if it doesn't exist
    try:
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
    except Exception as e:
        logger.error(f"Failed to create admin user: {str(e)}")
        db.session.rollback()

logger.info("PrivIoT application initialized successfully")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
