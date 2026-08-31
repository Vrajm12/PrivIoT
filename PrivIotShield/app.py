import os
import logging
from datetime import datetime
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

# Production Health, Readiness & Observability Endpoints
@app.route('/health')
def health_check():
    return {"status": "healthy", "version": "3.0.0", "timestamp": datetime.utcnow().isoformat()}, 200

@app.route('/ready')
def readiness_check():
    try:
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        return {"status": "ready", "database": "connected"}, 200
    except Exception as e:
        logger.error(f"Readiness probe failed: {e}")
        return {"status": "unready", "database": "disconnected", "error": str(e)}, 503

@app.route('/metrics')
def prometheus_metrics():
    try:
        from models import Asset, Collector, Alert, Observation
        assets_count = Asset.query.count()
        collectors_count = Collector.query.count()
        open_alerts_count = Alert.query.filter_by(status='OPEN').count()
        total_observations = Observation.query.count()
        return (
            f"# HELP priviot_assets_total Total discovered assets\n"
            f"# TYPE priviot_assets_total gauge\n"
            f"priviot_assets_total {assets_count}\n"
            f"# HELP priviot_collectors_total Total registered collectors\n"
            f"# TYPE priviot_collectors_total gauge\n"
            f"priviot_collectors_total {collectors_count}\n"
            f"# HELP priviot_open_alerts_total Total open alerts\n"
            f"# TYPE priviot_open_alerts_total gauge\n"
            f"priviot_open_alerts_total {open_alerts_count}\n"
            f"# HELP priviot_observations_total Total recorded observation events\n"
            f"# TYPE priviot_observations_total counter\n"
            f"priviot_observations_total {total_observations}\n"
        ), 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        return f"# Error collecting metrics: {str(e)}\n", 500, {'Content-Type': 'text/plain'}

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
    csrf.exempt(api_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    logger.info("API blueprint registered and CSRF exempted successfully")
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

    # Seed initial pilot inventory if empty
    try:
        from models import Asset, Device
        if Asset.query.count() == 0:
            admin_user = User.query.filter_by(username='admin').first()
            admin_id = admin_user.id if admin_user else 1
            pilot_assets = [
                Asset(tenant_id="default_tenant", user_id=admin_id, ip_address="192.168.1.101", mac_address="00:12:17:88:41:A2", vendor="Hikvision", model="DS-2CD2042WD-I", device_type="IP Camera", identity_confidence=0.92, network_scope="HQ Alpha (192.168.1.0/24)"),
                Asset(tenant_id="default_tenant", user_id=admin_id, ip_address="192.168.1.102", mac_address="50:C7:BF:12:34:56", vendor="TP-Link", model="Kasa HS100", device_type="Smart Plug", identity_confidence=0.88, network_scope="HQ Alpha (192.168.1.0/24)"),
                Asset(tenant_id="default_tenant", user_id=admin_id, ip_address="192.168.1.103", mac_address="CC:6E:A4:91:02:11", vendor="Samsung", model="QN65Q80B", device_type="Smart TV", identity_confidence=0.85, network_scope="HQ Alpha (192.168.1.0/24)"),
                Asset(tenant_id="default_tenant", user_id=admin_id, ip_address="192.168.1.104", mac_address="00:1E:0B:44:99:AA", vendor="HP", model="LaserJet Enterprise M608", device_type="Printer", identity_confidence=0.90, network_scope="HQ Alpha (192.168.1.0/24)"),
                Asset(tenant_id="default_tenant", user_id=admin_id, ip_address="192.168.1.107", mac_address="94:E6:86:99:88:77", vendor="Generic Espressif", model="ESP32 Board", device_type="Generic IoT", identity_confidence=0.42, network_scope="HQ Alpha (192.168.1.0/24)")
            ]
            db.session.add_all(pilot_assets)
            
            for pa in pilot_assets:
                d = Device(name=f"{pa.vendor} {pa.model}", device_type=pa.device_type, manufacturer=pa.vendor, model=pa.model, ip_address=pa.ip_address, mac_address=pa.mac_address, user_id=admin_id)
                db.session.add(d)
            
            db.session.commit()
            logger.info("Pilot lab inventory seeded successfully")
    except Exception as e:
        logger.warning(f"Pilot asset seeding note: {e}")
        db.session.rollback()

logger.info("PrivIoT application initialized successfully")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
