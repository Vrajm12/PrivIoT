"""
Root models.py backward compatibility proxy.
Imports all models and helpers from priviot.data.models.
"""
from priviot.data.models import (
    User, Device, Scan, Vulnerability, PrivacyIssue, Report, UserActivity, DeviceGroup,
    Asset, AssetService, RiskAssessment, ContainmentIntent, AuditEvent, ScanJob,
    Collector, Observation, BehavioralBaseline, BehavioralDriftEvent, Alert,
    GatewayCredential, ScheduledScan, load_user
)

__all__ = [
    "User", "Device", "Scan", "Vulnerability", "PrivacyIssue", "Report", "UserActivity", "DeviceGroup",
    "Asset", "AssetService", "RiskAssessment", "ContainmentIntent", "AuditEvent", "ScanJob",
    "Collector", "Observation", "BehavioralBaseline", "BehavioralDriftEvent", "Alert",
    "GatewayCredential", "ScheduledScan", "load_user"
]
