import os
from app import app, db
from models import User
from werkzeug.security import generate_password_hash
import secrets

# Create database tables
with app.app_context():
    print("Creating database tables...")
    db.create_all()
    
    # Create admin user if it doesn't exist
    admin_exists = User.query.filter_by(username='admin').first()
    if not admin_exists:
        print("Creating admin user...")
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            api_key=secrets.token_hex(16)
        )
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user created with API key: {admin_user.api_key}")
    else:
        print("Admin user already exists")
        
    print("Database initialization complete!")