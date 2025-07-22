from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime
import json
import secrets


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
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    api_key = db.Column(db.String(64), unique=True)
    notification_preferences = db.Column(db.Text)  # JSON string for notification settings
    phone = db.Column(db.String(20))  # For SMS notifications
    
    # Relationships
    devices = db.relationship('Device', backref='owner', lazy='dynamic')
    scans = db.relationship('Scan', backref='user', lazy='dynamic')
    reports = db.relationship('Report', backref='user', lazy='dynamic')
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if not self.api_key:
            self.api_key = secrets.token_hex(32)
        if not self.notification_preferences:
            self.notification_preferences = json.dumps({
                'email_enabled': True,
                'sms_enabled': False,
                'severity_threshold': 'high',
                'scan_completion': True,
                'vulnerability_alerts': True
            })
    
    def get_notification_preferences(self):
        """Get user notification preferences as dict"""
        try:
            return json.loads(self.notification_preferences or '{}')
        except (json.JSONDecodeError, TypeError):
            return {
                'email_enabled': True,
                'sms_enabled': False,
                'severity_threshold': 'high',
                'scan_completion': True,
                'vulnerability_alerts': True
            }
    
    def set_notification_preferences(self, preferences):
        """Set user notification preferences"""
        self.notification_preferences = json.dumps(preferences)
    
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
    last_scan_date = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    tags = db.Column(db.Text)  # JSON string for device tags
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    scans = db.relationship('Scan', backref='device', lazy='dynamic')
    
    def get_latest_scan(self):
        """Get the most recent scan for this device"""
        return self.scans.order_by(Scan.scan_date.desc()).first()
    
    def get_security_status(self):
        """Get current security status based on latest scan"""
        latest_scan = self.get_latest_scan()
        if not latest_scan or latest_scan.status != 'completed':
            return 'unknown'
        
        if latest_scan.security_score >= 8.0:
            return 'excellent'
        elif latest_scan.security_score >= 6.0:
            return 'good'
        elif latest_scan.security_score >= 4.0:
            return 'fair'
        else:
            return 'poor'
    
    def get_tags(self):
        """Get device tags as list"""
        try:
            return json.loads(self.tags or '[]')
        except (json.JSONDecodeError, TypeError):
            return []
    
    def set_tags(self, tags):
        """Set device tags"""
        self.tags = json.dumps(tags)
    
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
    scan_duration = db.Column(db.Float)  # Duration in seconds
    anomalies_detected = db.Column(db.Integer, default=0)
    
    # Foreign keys
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic')
    privacy_issues = db.relationship('PrivacyIssue', backref='scan', lazy='dynamic')
    
    def get_vulnerability_counts(self):
        """Get vulnerability counts by severity"""
        vulns = self.vulnerabilities.all()
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulns:
            if vuln.severity in counts:
                counts[vuln.severity] += 1
        return counts
    
    def get_privacy_issue_counts(self):
        """Get privacy issue counts by severity"""
        issues = self.privacy_issues.all()
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for issue in issues:
            if issue.severity in counts:
                counts[issue.severity] += 1
        return counts
    
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
    remediation_steps = db.Column(db.Text)  # JSON string for step-by-step remediation
    auto_remediable = db.Column(db.Boolean, default=False)
    remediation_complexity = db.Column(db.String(20), default='medium')  # low, medium, high
    estimated_fix_time = db.Column(db.String(50))  # e.g., "5 minutes", "1 hour"
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    # Foreign key
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    
    def get_remediation_steps(self):
        """Get remediation steps as list"""
        try:
            return json.loads(self.remediation_steps or '[]')
        except (json.JSONDecodeError, TypeError):
            return []
    
    def set_remediation_steps(self, steps):
        """Set remediation steps"""
        self.remediation_steps = json.dumps(steps)
    
    def get_priority_score(self):
        """Calculate priority score based on CVSS and other factors"""
        base_score = self.cvss_score or 0
        
        # Adjust based on device criticality and exposure
        if hasattr(self.scan, 'device'):
            device_type = self.scan.device.device_type.lower()
            if 'camera' in device_type or 'lock' in device_type:
                base_score += 1  # Higher priority for security-critical devices
        
        return min(10.0, base_score)
    
    def __repr__(self):
        return f'<Vulnerability {self.name}>'


class PrivacyIssue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # low, medium, high, critical
    privacy_impact = db.Column(db.Float)  # 0-10 score
    status = db.Column(db.String(20), default='open')  # open, resolved, false_positive
    data_types_affected = db.Column(db.Text)  # JSON string for types of data affected
    compliance_impact = db.Column(db.Text)  # GDPR, CCPA, etc.
    recommendation = db.Column(db.Text)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    # Foreign key
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    
    def get_data_types_affected(self):
        """Get affected data types as list"""
        try:
            return json.loads(self.data_types_affected or '[]')
        except (json.JSONDecodeError, TypeError):
            return []
    
    def set_data_types_affected(self, data_types):
        """Set affected data types"""
        self.data_types_affected = json.dumps(data_types)
    
    def __repr__(self):
        return f'<PrivacyIssue {self.name}>'


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    report_type = db.Column(db.String(50))  # detailed, summary, executive
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    file_path = db.Column(db.String(255))  # Path to generated file (PDF, etc.)
    file_size = db.Column(db.Integer)  # File size in bytes
    download_count = db.Column(db.Integer, default=0)
    content = db.Column(db.Text)
    
    # Foreign keys
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    scan = db.relationship('Scan', backref='reports')
    
    def increment_download_count(self):
        """Increment download counter"""
        self.download_count = (self.download_count or 0) + 1
    
    def __repr__(self):
        return f'<Report {self.title}>'


class UserActivity(db.Model):
    """Track user activity for analytics and security"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)  # login, scan, report_generate, etc.
    activity_data = db.Column(db.Text)  # JSON string for additional data
    ip_address = db.Column(db.String(45))  # Support IPv6
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='activities')
    
    def __repr__(self):
        return f'<UserActivity {self.activity_type} by {self.user_id}>'


class DeviceGroup(db.Model):
    """Group devices for better organization"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    color = db.Column(db.String(7), default='#6366F1')  # Hex color for UI
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    user = db.relationship('User', backref='device_groups')
    
    def __repr__(self):
        return f'<DeviceGroup {self.name}>'


# Association table for many-to-many relationship between devices and groups
device_group_association = db.Table('device_group_association',
    db.Column('device_id', db.Integer, db.ForeignKey('device.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('device_group.id'), primary_key=True)
)

# Add relationship to Device model
Device.groups = db.relationship('DeviceGroup', secondary=device_group_association, backref='devices')
