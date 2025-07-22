from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime
import json


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    api_key = db.Column(db.String(64), unique=True)
    
    # Relationships
    devices = db.relationship('Device', backref='owner', lazy='dynamic')
    scans = db.relationship('Scan', backref='user', lazy='dynamic')
    
    def __repr__(self):
        return f'<User {self.username}>'


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    device_type = db.Column(db.String(50), nullable=False)
    manufacturer = db.Column(db.String(100))
    model = db.Column(db.String(100))
    firmware_version = db.Column(db.String(50))
    ip_address = db.Column(db.String(15))
    mac_address = db.Column(db.String(17))
    location = db.Column(db.String(100))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    scans = db.relationship('Scan', backref='device', lazy='dynamic')
    
    def __repr__(self):
        return f'<Device {self.name}>'


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    security_score = db.Column(db.Float)  # 0-10 score based on CVSS
    privacy_score = db.Column(db.Float)  # 0-10 score
    overall_score = db.Column(db.Float)  # Combined score
    risk_level = db.Column(db.String(20))  # low, medium, high, critical
    
    # Store raw scan data as JSON
    scan_data = db.Column(db.Text)
    
    # Foreign keys
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic')
    privacy_issues = db.relationship('PrivacyIssue', backref='scan', lazy='dynamic')
    
    def __repr__(self):
        return f'<Scan {self.id} for device {self.device_id}>'
    
    def get_scan_data(self):
        if self.scan_data:
            return json.loads(self.scan_data)
        return {}


class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # low, medium, high, critical
    cvss_score = db.Column(db.Float)  # 0-10 score
    cvss_vector = db.Column(db.String(100))
    status = db.Column(db.String(20), default='open')  # open, resolved, false_positive
    recommendation = db.Column(db.Text)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign key
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    
    def __repr__(self):
        return f'<Vulnerability {self.name}>'


class PrivacyIssue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # low, medium, high, critical
    privacy_impact = db.Column(db.Float)  # 0-10 score
    status = db.Column(db.String(20), default='open')  # open, resolved, false_positive
    recommendation = db.Column(db.Text)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign key
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    
    def __repr__(self):
        return f'<PrivacyIssue {self.name}>'


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    report_type = db.Column(db.String(50))  # detailed, summary, executive
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    content = db.Column(db.Text)
    
    # Foreign keys
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    scan = db.relationship('Scan', backref='reports')
    
    def __repr__(self):
        return f'<Report {self.title}>'
