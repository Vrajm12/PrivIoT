import os
import logging
import json
from datetime import datetime
from twilio.rest import Client
from app import app
from models import User

# Configure logging
logger = logging.getLogger(__name__)

# Twilio credentials
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER")

# Alert severity levels
SEVERITY_LEVELS = {
    "critical": {
        "name": "CRITICAL",
        "threshold": 9.0,
        "description": "Immediate action required. High likelihood of exploit with severe impact."
    },
    "high": {
        "name": "HIGH",
        "threshold": 7.0,
        "description": "Urgent action required. Significant security risk."
    },
    "medium": {
        "name": "MEDIUM",
        "threshold": 4.0,
        "description": "Action recommended. Moderate security risk."
    },
    "low": {
        "name": "LOW",
        "threshold": 0.1,
        "description": "Low priority. Minimal security risk."
    }
}

def send_sms_alert(phone_number, message):
    """
    Send SMS alert using Twilio
    
    Args:
        phone_number (str): Recipient's phone number
        message (str): Alert message to send
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
        logger.warning("Twilio credentials not configured. SMS alert not sent.")
        return False
    
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        logger.info(f"SMS alert sent successfully. SID: {message.sid}")
        return True
    except Exception as e:
        logger.error(f"Failed to send SMS alert: {str(e)}")
        return False

def send_email_alert(email, subject, body):
    """
    Send email alert (placeholder for email implementation)
    
    Args:
        email (str): Recipient's email address
        subject (str): Email subject
        body (str): Email body (HTML content)
        
    Returns:
        bool: True if successful, False otherwise
    """
    # This is a placeholder for email sending functionality
    # In a production environment, implement with a service like SendGrid, Mailgun, etc.
    logger.info(f"Email alert would be sent to {email} with subject: {subject}")
    return True

def create_vulnerability_alert(user, device, vulnerability, scan):
    """
    Create and send alert for a new vulnerability
    
    Args:
        user (User): User object
        device (Device): Device object
        vulnerability (Vulnerability): Vulnerability object
        scan (Scan): Scan object
        
    Returns:
        bool: True if alert was sent, False otherwise
    """
    try:
        # Format message
        severity = vulnerability.severity.lower()
        severity_info = SEVERITY_LEVELS.get(severity, SEVERITY_LEVELS["medium"])
        
        message = f"PrivIoT ALERT: {severity_info['name']} vulnerability detected\n"
        message += f"Device: {device.name}\n"
        message += f"Issue: {vulnerability.name}\n"
        message += f"CVSS Score: {vulnerability.cvss_score}\n"
        message += f"Detected: {vulnerability.detected_at.strftime('%Y-%m-%d %H:%M')}\n"
        message += f"\nPlease login to PrivIoT dashboard for details and remediation steps."
        
        # Determine if this alert meets threshold for SMS
        # Only send SMS for high and critical vulnerabilities
        should_send_sms = severity in ["critical", "high"]
        
        # In a production app, would check user preferences here
        if should_send_sms and hasattr(user, 'phone') and user.phone:
            send_sms_alert(user.phone, message)
        
        # Send email alert (to be implemented with email service)
        email_subject = f"PrivIoT Security Alert: {severity_info['name']} Vulnerability Detected"
        email_body = f"""
        <h2>Security Alert: {severity_info['name']} Vulnerability</h2>
        <p>A {severity} security vulnerability has been detected on your device.</p>
        
        <h3>Details:</h3>
        <ul>
            <li><strong>Device:</strong> {device.name}</li>
            <li><strong>Vulnerability:</strong> {vulnerability.name}</li>
            <li><strong>Description:</strong> {vulnerability.description}</li>
            <li><strong>CVSS Score:</strong> {vulnerability.cvss_score}</li>
            <li><strong>Severity:</strong> {severity.upper()}</li>
            <li><strong>Detection Time:</strong> {vulnerability.detected_at.strftime('%Y-%m-%d %H:%M')}</li>
        </ul>
        
        <h3>Recommended Action:</h3>
        <p>{vulnerability.recommendation}</p>
        
        <p><a href="#">View Details in PrivIoT Dashboard</a></p>
        """
        
        if hasattr(user, 'email') and user.email:
            send_email_alert(user.email, email_subject, email_body)
        
        # Log the alert
        logger.info(f"Vulnerability alert created for user {user.id}, device {device.id}, vulnerability {vulnerability.id}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to create vulnerability alert: {str(e)}")
        return False

def create_anomaly_alert(user, device, anomaly_data):
    """
    Create and send alert for an anomalous behavior
    
    Args:
        user (User): User object
        device (Device): Device object
        anomaly_data (dict): Anomaly detection data
        
    Returns:
        bool: True if alert was sent, False otherwise
    """
    try:
        severity = anomaly_data.get('severity', 'medium').lower()
        severity_info = SEVERITY_LEVELS.get(severity, SEVERITY_LEVELS["medium"])
        
        message = f"PrivIoT ALERT: Anomalous behavior detected\n"
        message += f"Device: {device.name}\n"
        message += f"Type: {anomaly_data.get('type', 'Unknown')}\n"
        message += f"Severity: {severity_info['name']}\n"
        message += f"Detected: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}\n"
        message += f"\nPlease login to PrivIoT dashboard to investigate."
        
        # Only send SMS for high and critical anomalies
        should_send_sms = severity in ["critical", "high"]
        
        if should_send_sms and hasattr(user, 'phone') and user.phone:
            send_sms_alert(user.phone, message)
        
        # Send email alert (to be implemented with email service)
        email_subject = f"PrivIoT Alert: Anomalous Behavior Detected"
        email_body = f"""
        <h2>Security Alert: Anomalous Behavior</h2>
        <p>Unusual behavior has been detected on your IoT device that may indicate a security issue.</p>
        
        <h3>Details:</h3>
        <ul>
            <li><strong>Device:</strong> {device.name}</li>
            <li><strong>Anomaly Type:</strong> {anomaly_data.get('type', 'Unknown')}</li>
            <li><strong>Description:</strong> {anomaly_data.get('description', 'No description available')}</li>
            <li><strong>Severity:</strong> {severity.upper()}</li>
            <li><strong>Detection Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}</li>
        </ul>
        
        <h3>Recommended Action:</h3>
        <p>{anomaly_data.get('recommendation', 'Investigate the device behavior and consider network isolation if suspicious activity continues.')}</p>
        
        <p><a href="#">View Details in PrivIoT Dashboard</a></p>
        """
        
        if hasattr(user, 'email') and user.email:
            send_email_alert(user.email, email_subject, email_body)
        
        # Log the alert
        logger.info(f"Anomaly alert created for user {user.id}, device {device.id}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to create anomaly alert: {str(e)}")
        return False