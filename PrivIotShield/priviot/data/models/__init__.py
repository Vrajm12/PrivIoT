from extensions import db, login_manager
from flask_login import UserMixin
from datetime import datetime
import json
import secrets
import uuid


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


# ==============================================================================
# Canonical Enterprise Entities (Phase 1.5: Hardened Continuous IoT Exposure & Containment)
# ==============================================================================

class Asset(db.Model):
    """
    Canonical Asset Entity representing a physical/logical connected IoT/OT device.
    Supports deterministic multi-vector reconciliation, DHCP history tracking, and tenant isolation.
    """
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    mac_address = db.Column(db.String(17), index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    hostname = db.Column(db.String(255))
    
    # Inferred / Evidence-Backed Identity
    vendor = db.Column(db.String(100))
    manufacturer = db.Column(db.String(100))
    model = db.Column(db.String(100))
    device_type = db.Column(db.String(64), default='Generic IoT Device')
    firmware_version = db.Column(db.String(64))
    serial_number = db.Column(db.String(128))
    
    # Confidence & Evidence
    identity_confidence = db.Column(db.Float, default=0.3)  # 0.0 to 1.0 (Probabilistic, not absolute)
    identity_evidence = db.Column(db.Text)  # Structured JSON IdentityEvidence claims
    
    # Identity & Address History (Protects against DHCP churn and IP reuse)
    ip_history = db.Column(db.Text)        # JSON list of [{"ip": "...", "seen_at": "..."}]
    mac_history = db.Column(db.Text)       # JSON list of [{"mac": "...", "seen_at": "..."}]
    identity_history = db.Column(db.Text)  # JSON list of previous fingerprint claims
    reconciliation_method = db.Column(db.String(32), default='mac_address')  # mac_address, corroborated_fingerprint, ip_fallback
    
    # Telemetry & Placement
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    discovery_source = db.Column(db.String(64), default='safe_active_probe')
    network_scope = db.Column(db.String(64))
    ownership = db.Column(db.String(128))
    criticality = db.Column(db.String(20), default='tier_2')  # tier_1 (critical), tier_2 (standard), tier_3 (peripheral)
    lifecycle_status = db.Column(db.String(20), default='active')  # active, eol, unsupported, decommissioned
    
    # Multitenancy
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # Relationships
    services = db.relationship('AssetService', backref='asset', cascade='all, delete-orphan', lazy='dynamic')
    risk_assessments = db.relationship('RiskAssessment', backref='asset', cascade='all, delete-orphan', lazy='dynamic')
    containment_intents = db.relationship('ContainmentIntent', backref='asset', cascade='all, delete-orphan', lazy='dynamic')
    observations = db.relationship('Observation', backref='asset', cascade='all, delete-orphan', lazy='dynamic')
    baselines = db.relationship('BehavioralBaseline', backref='asset', cascade='all, delete-orphan', lazy='dynamic')
    drift_events = db.relationship('BehavioralDriftEvent', backref='asset', cascade='all, delete-orphan', lazy='dynamic')
    alerts = db.relationship('Alert', backref='asset', cascade='all, delete-orphan', lazy='dynamic')

    def get_evidence(self):
        try:
            return json.loads(self.identity_evidence or '{}')
        except Exception:
            return {}

    def set_evidence(self, evidence_dict):
        self.identity_evidence = json.dumps(evidence_dict)

    def get_ip_history(self):
        try:
            return json.loads(self.ip_history or '[]')
        except Exception:
            return []

    def get_latest_risk(self):
        return self.risk_assessments.order_by(RiskAssessment.assessed_at.desc()).first()

    def get_active_containment(self):
        return self.containment_intents.filter(
            ContainmentIntent.status.in_(['GENERATED', 'VALIDATED', 'PENDING_APPROVAL', 'APPROVED', 'APPLYING', 'APPLIED_UNVERIFIED', 'VERIFIED', 'recommended', 'previewed', 'approved', 'applied'])
        ).order_by(ContainmentIntent.created_at.desc()).first()

    def get_active_baseline(self):
        return self.baselines.order_by(BehavioralBaseline.last_updated.desc()).first()

    def get_trust_profile(self):
        """
        Canonical Device Trust Profile compiling current multi-vector security truth.
        """
        latest_risk = self.get_latest_risk()
        active_containment = self.get_active_containment()
        active_baseline = self.get_active_baseline()
        open_alerts = self.alerts.filter_by(status='OPEN').all()
        recent_drifts = self.drift_events.order_by(BehavioralDriftEvent.created_at.desc()).limit(10).all()

        services_list = [s.to_dict() for s in self.services.all()]
        
        # Pull vulnerability intel
        from vuln_intel import vuln_engine
        vuln_matches = vuln_engine.get_vulnerabilities_for_device({
            "manufacturer": self.vendor or self.manufacturer,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "device_type": self.device_type,
            "open_ports": [s.port for s in self.services.all()],
            "services": [s.service_name for s in self.services.all()]
        })

        return {
            "asset_id": self.id,
            "uuid": self.uuid,
            "tenant_id": self.tenant_id,
            "identity": {
                "vendor": self.vendor or self.manufacturer or "Unknown",
                "manufacturer": self.manufacturer or self.vendor or "Unknown",
                "model": self.model or "Unknown Model",
                "device_type": self.device_type,
                "firmware_version": self.firmware_version or "Unknown",
                "serial_number": self.serial_number,
                "identity_confidence": self.identity_confidence,
                "identity_evidence": self.get_evidence(),
                "reconciliation_method": self.reconciliation_method
            },
            "network": {
                "current_ip": self.ip_address,
                "ip_history": self.get_ip_history(),
                "mac_address": self.mac_address,
                "hostname": self.hostname,
                "network_scope": self.network_scope or "Unknown Subnet",
                "first_seen": self.first_seen.isoformat() if self.first_seen else None,
                "last_seen": self.last_seen.isoformat() if self.last_seen else None
            },
            "services": {
                "total_services": len(services_list),
                "services": services_list
            },
            "vulnerabilities": {
                "count": len(vuln_matches),
                "items": vuln_matches
            },
            "exposure": {
                "criticality": self.criticality,
                "lifecycle_status": self.lifecycle_status,
                "network_placement": "flat_lan",
                "open_ports_count": len(services_list)
            },
            "behavior": {
                "baseline_status": active_baseline.status if active_baseline else "LEARNING",
                "baseline": active_baseline.to_dict() if active_baseline else None,
                "active_drifts_count": len(recent_drifts),
                "recent_drifts": [d.to_dict() for d in recent_drifts]
            },
            "risk": {
                "pri_score": latest_risk.pri_score if latest_risk else None,
                "pri_level": latest_risk.pri_level if latest_risk else "unknown",
                "risk_model_version": latest_risk.risk_model_version if latest_risk else "pri-v2",
                "breakdown": latest_risk.to_dict()["breakdown"] if latest_risk else {},
                "explanation": latest_risk.get_explanation() if latest_risk else {}
            },
            "remediation": {
                "active_containment": active_containment.to_dict() if active_containment else None,
                "containment_status": active_containment.status if active_containment else "NONE",
                "provider": active_containment.applied_provider if active_containment else None
            },
            "alerts": {
                "open_count": len(open_alerts),
                "open_alerts": [a.to_dict() for a in open_alerts]
            }
        }

    def to_dict(self):
        latest_risk = self.get_latest_risk()
        return {
            "id": self.id,
            "uuid": self.uuid,
            "tenant_id": self.tenant_id,
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "vendor": self.vendor or self.manufacturer or "Unknown",
            "model": self.model or "Unknown Model",
            "device_type": self.device_type,
            "firmware_version": self.firmware_version or "Unknown",
            "serial_number": self.serial_number,
            "identity_confidence": self.identity_confidence,
            "identity_evidence": self.get_evidence(),
            "reconciliation_method": self.reconciliation_method,
            "ip_history": self.get_ip_history(),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "criticality": self.criticality,
            "lifecycle_status": self.lifecycle_status,
            "services_count": self.services.count(),
            "latest_pri": latest_risk.pri_score if latest_risk else None,
            "pri_level": latest_risk.pri_level if latest_risk else "unknown"
        }

    def __repr__(self):
        return f'<Asset {self.uuid[:8]} ({self.ip_address} - {self.vendor})>'


class AssetService(db.Model):
    """
    Inventory of detected services and open listening ports on an Asset with evidence-backed security semantics.
    """
    __tablename__ = 'asset_services'

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default='tcp')  # tcp, udp
    service_name = db.Column(db.String(64), nullable=False)  # http, https, rtsp, mqtt, telnet, ssh, upnp, snmp
    version_banner = db.Column(db.String(255))
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_status = db.Column(db.String(32), default='NOT_ASSESSED')  # UNKNOWN, PLAINTEXT, TLS, DTLS, ENCRYPTED, NOT_ASSESSED
    auth_indication = db.Column(db.String(32), default='NOT_ASSESSED')    # UNKNOWN, OBSERVED_NO_AUTH, AUTH_REQUIRED, AUTHENTICATION_FAILED, NOT_ASSESSED
    evidence = db.Column(db.Text)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "port": self.port,
            "protocol": self.protocol,
            "service_name": self.service_name,
            "version_banner": self.version_banner,
            "is_encrypted": self.is_encrypted,
            "encryption_status": self.encryption_status,
            "auth_indication": self.auth_indication,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None
        }


class RiskAssessment(db.Model):
    """
    Deterministic, mathematically explainable PrivIoT Risk Index (PRI) calculation record.
    """
    __tablename__ = 'risk_assessments'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    risk_model_version = db.Column(db.String(16), default='pri-v1')
    threat_base = db.Column(db.Float, default=0.0)
    cisa_kev_boost = db.Column(db.Float, default=0.0)
    epss_signal = db.Column(db.Float, default=0.0)
    exposure_factor = db.Column(db.Float, default=0.8)
    criticality_weight = db.Column(db.Float, default=1.0)
    behavioral_penalty = db.Column(db.Float, default=0.0)
    compliance_penalty = db.Column(db.Float, default=0.0)
    pri_score = db.Column(db.Float, nullable=False)
    pri_level = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    explanation_json = db.Column(db.Text)
    assessed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_explanation(self):
        try:
            return json.loads(self.explanation_json or '{}')
        except Exception:
            return {}

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "risk_model_version": self.risk_model_version,
            "pri_score": self.pri_score,
            "pri_level": self.pri_level,
            "breakdown": {
                "threat_base": self.threat_base,
                "cisa_kev_boost": self.cisa_kev_boost,
                "epss_signal": self.epss_signal,
                "exposure_factor": self.exposure_factor,
                "criticality_weight": self.criticality_weight,
                "behavioral_penalty": self.behavioral_penalty,
                "compliance_penalty": self.compliance_penalty
            },
            "explanation": self.get_explanation(),
            "assessed_at": self.assessed_at.isoformat() if self.assessed_at else None
        }


class ContainmentIntent(db.Model):
    """
    Intermediate representation of network containment policy with explicit semantics and rollback limitation notes.
    """
    __tablename__ = 'containment_intents'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), default='high')
    desired_effect = db.Column(db.String(255), default='Block lateral traversal and unauthenticated egress')
    
    # Structured Policy Specification
    policy_rules_json = db.Column(db.Text)      # List of structured rules {action: ALLOW|DENY|OBSERVE, ...}
    allowed_destinations = db.Column(db.Text)   # JSON list
    blocked_destinations = db.Column(db.Text)   # JSON list
    allowed_ports = db.Column(db.Text)          # JSON list
    blocked_ports = db.Column(db.Text)          # JSON list
    protocol = db.Column(db.String(20), default='ALL')
    
    # State & Lifecycle
    status = db.Column(db.String(32), default='GENERATED')  # GENERATED, VALIDATED, APPLIED_UNVERIFIED, VERIFIED, FAILED, ROLLED_BACK
    approved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    applied_provider = db.Column(db.String(32))             # pfsense, unifi, iptables, pihole
    generated_policy = db.Column(db.Text)
    rollback_policy = db.Column(db.Text)
    rollback_limitation = db.Column(db.String(255))         # Specific notes on manual or programmatic rollback boundaries
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "reason": self.reason,
            "severity": self.severity,
            "desired_effect": self.desired_effect,
            "status": self.status,
            "applied_provider": self.applied_provider,
            "allowed_destinations": json.loads(self.allowed_destinations or '[]'),
            "blocked_destinations": json.loads(self.blocked_destinations or '[]'),
            "allowed_ports": json.loads(self.allowed_ports or '[]'),
            "blocked_ports": json.loads(self.blocked_ports or '[]'),
            "generated_policy": self.generated_policy,
            "rollback_limitation": self.rollback_limitation,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class AuditEvent(db.Model):
    """
    Immutable audit log entry for every operational and containment action.
    """
    __tablename__ = 'audit_events'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    actor_username = db.Column(db.String(64), default='system')
    action = db.Column(db.String(64), nullable=False)
    target_type = db.Column(db.String(32))
    target_id = db.Column(db.String(64))
    request_id = db.Column(db.String(64))
    details_json = db.Column(db.Text)
    result = db.Column(db.String(20), default='success')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "actor": self.actor_username,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "request_id": self.request_id,
            "details": json.loads(self.details_json or '{}'),
            "result": self.result,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


class ScanJob(db.Model):
    """
    Stateful Scan Execution record with scope boundaries, rate limits, and audit tracking.
    """
    __tablename__ = 'scan_jobs'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    scan_uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_scope = db.Column(db.String(128), nullable=False)
    profile = db.Column(db.String(32), default='safe')
    status = db.Column(db.String(32), default='pending')
    rate_limit = db.Column(db.Integer, default=50)
    concurrency_limit = db.Column(db.Integer, default=10)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    discovered_count = db.Column(db.Integer, default=0)
    summary_json = db.Column(db.Text)
    error_message = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "scan_uuid": self.scan_uuid,
            "target_scope": self.target_scope,
            "profile": self.profile,
            "status": self.status,
            "discovered_count": self.discovered_count,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "error_message": self.error_message,
            "summary": json.loads(self.summary_json or '{}')
        }


# ==============================================================================
# Phase 2: Observation Event Store, Telemetry Collectors, Baseline & Drift
# ==============================================================================

class Collector(db.Model):
    """
    Registered telemetry sensor/collector node with token authentication.
    """
    __tablename__ = 'collectors'

    id = db.Column(db.Integer, primary_key=True)
    collector_uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    site_id = db.Column(db.String(64), default='default_site', index=True)
    network_scope = db.Column(db.String(128))
    name = db.Column(db.String(128), nullable=False)
    collector_type = db.Column(db.String(32), default='passive_packet')  # passive_packet, dns, netflow, ebpf
    auth_token_hash = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='offline')  # online, offline, degraded
    version = db.Column(db.String(32), default='2.0.0')
    last_heartbeat = db.Column(db.DateTime)
    capabilities_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "collector_uuid": self.collector_uuid,
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "name": self.name,
            "network_scope": self.network_scope,
            "collector_type": self.collector_type,
            "status": self.status,
            "version": self.version,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "capabilities": json.loads(self.capabilities_json or '[]')
        }


class Observation(db.Model):
    """
    Append-Only Event Store for raw telemetry and continuous observation events.
    """
    __tablename__ = 'observations'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=True, index=True)
    collector_id = db.Column(db.Integer, db.ForeignKey('collectors.id'), nullable=True)
    observation_type = db.Column(db.String(32), nullable=False, index=True)  # network, dns, service, identity, vulnerability, behavior, containment
    source = db.Column(db.String(64), default='sensor')  # live_packet, pcap, netflow, active_probe
    payload_json = db.Column(db.Text, nullable=False)
    confidence = db.Column(db.Float, default=1.0)
    evidence_ref = db.Column(db.String(128))
    correlation_id = db.Column(db.String(64), index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "collector_id": self.collector_id,
            "observation_type": self.observation_type,
            "source": self.source,
            "payload": json.loads(self.payload_json or '{}'),
            "confidence": self.confidence,
            "evidence_ref": self.evidence_ref,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


class BehavioralBaseline(db.Model):
    """
    Synthetic MUD Baseline entity tracking persistent normal communication parameters.
    """
    __tablename__ = 'behavioral_baselines'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False, index=True)
    status = db.Column(db.String(32), default='LEARNING')  # LEARNING, STABLE, DRIFT_DETECTED, REVIEW_REQUIRED
    allowed_destinations = db.Column(db.Text)  # JSON list of normal IPs/hostnames
    allowed_ports = db.Column(db.Text)         # JSON list of destination ports
    allowed_protocols = db.Column(db.Text)     # JSON list of protocols
    dns_whitelist = db.Column(db.Text)         # JSON list of queried domains
    communication_frequency = db.Column(db.Text) # JSON stats on connection count/intervals
    learning_start = db.Column(db.DateTime, default=datetime.utcnow)
    learning_end = db.Column(db.DateTime)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    summary_json = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "status": self.status,
            "allowed_destinations": json.loads(self.allowed_destinations or '[]'),
            "allowed_ports": json.loads(self.allowed_ports or '[]'),
            "allowed_protocols": json.loads(self.allowed_protocols or '[]'),
            "dns_whitelist": json.loads(self.dns_whitelist or '[]'),
            "learning_start": self.learning_start.isoformat() if self.learning_start else None,
            "learning_end": self.learning_end.isoformat() if self.learning_end else None,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "summary": json.loads(self.summary_json or '{}')
        }


class BehavioralDriftEvent(db.Model):
    """
    Explainable anomaly record generated when live traffic deviates from established baseline.
    """
    __tablename__ = 'behavioral_drift_events'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False, index=True)
    drift_type = db.Column(db.String(64), nullable=False)  # new_destination_ip, new_destination_port, unclassified_dns, protocol_mismatch
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    observed_behavior_json = db.Column(db.Text, nullable=False)
    expected_baseline_json = db.Column(db.Text, nullable=False)
    difference_description = db.Column(db.String(255), nullable=False)
    confidence = db.Column(db.Float, default=0.8)
    evidence_json = db.Column(db.Text)
    status = db.Column(db.String(32), default='OPEN')  # OPEN, INVESTIGATING, ACCEPTED_BASELINE, CONTAINED
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "drift_type": self.drift_type,
            "severity": self.severity,
            "observed_behavior": json.loads(self.observed_behavior_json or '{}'),
            "expected_baseline": json.loads(self.expected_baseline_json or '{}'),
            "difference": self.difference_description,
            "confidence": self.confidence,
            "evidence": json.loads(self.evidence_json or '{}'),
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class Alert(db.Model):
    """
    Deterministic alert entity linking evidence to operational events.
    """
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    alert_uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=True, index=True)
    alert_type = db.Column(db.String(64), nullable=False)  # new_high_risk_device, critical_cve, cisa_kev_match, risk_increase, behavioral_drift, suspicious_dns, cleartext_credential, containment_failure, collector_offline
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    evidence_json = db.Column(db.Text)
    status = db.Column(db.String(32), default='OPEN')  # OPEN, ACKNOWLEDGED, RESOLVED, SUPPRESSED
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    resolved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "alert_uuid": self.alert_uuid,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": json.loads(self.evidence_json or '{}'),
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None
        }


class GatewayCredential(db.Model):
    """
    Encrypted connector credentials for direct firewall API integrations.
    """
    __tablename__ = 'gateway_credentials'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    provider_type = db.Column(db.String(32), nullable=False)  # pfsense, unifi, iptables
    name = db.Column(db.String(128), nullable=False)
    endpoint_url = db.Column(db.String(255), nullable=False)
    encrypted_payload = db.Column(db.Text, nullable=False)  # Encrypted JSON containing API tokens/keys
    status = db.Column(db.String(32), default='active')     # active, unreachable, auth_failed
    last_tested = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "provider_type": self.provider_type,
            "name": self.name,
            "endpoint_url": self.endpoint_url,
            "status": self.status,
            "last_tested": self.last_tested.isoformat() if self.last_tested else None
        }


class ScheduledScan(db.Model):
    """
    Continuous recurring discovery schedule honoring ScanAuthorizationPolicy.
    """
    __tablename__ = 'scheduled_scans'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(64), default='default_tenant', nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    site_id = db.Column(db.String(64), default='default_site')
    target_scope = db.Column(db.String(128), nullable=False)
    profile = db.Column(db.String(32), default='safe')
    frequency = db.Column(db.String(32), default='daily')  # hourly, daily, custom_interval
    cron_expression = db.Column(db.String(64))
    is_active = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime)
    next_run = db.Column(db.DateTime)
    last_status = db.Column(db.String(32), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "target_scope": self.target_scope,
            "profile": self.profile,
            "frequency": self.frequency,
            "is_active": self.is_active,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "last_status": self.last_status
        }

