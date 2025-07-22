import json
import random
import logging
from datetime import datetime
from app import app
from ai_analyzer import analyze_device_security, analyze_privacy_risks
from cvss_calculator import calculate_cvss_score
from openai_integration import analyze_device_security_with_ai, analyze_privacy_risks_with_ai

# Configure logging
logger = logging.getLogger(__name__)


def scan_device(device):
    """
    Scan an IoT device for security vulnerabilities and privacy issues.
    In a real-world application, this would connect to the device and perform actual scanning.
    
    Args:
        device: Device object from the database
    
    Returns:
        dict: Scan results including vulnerabilities and privacy issues
    """
    app.logger.info(f"Starting security scan for device: {device.name} (ID: {device.id})")
    
    try:
        # Prepare device data for analysis
        device_data = {
            'id': device.id,
            'name': device.name,
            'device_type': device.device_type,
            'manufacturer': device.manufacturer,
            'model': device.model,
            'firmware_version': device.firmware_version,
            'ip_address': device.ip_address,
            'mac_address': device.mac_address,
            'location': device.location,
            'description': device.description
        }
        
        # Try to use enhanced AI analysis first, with fallback to standard analysis
        try:
            # Enhanced AI-powered security analysis
            security_analysis = analyze_device_security_with_ai(device_data)
            logger.info(f"Enhanced AI security analysis completed for device {device.name}")
        except Exception as e:
            logger.warning(f"Enhanced AI security analysis failed: {e}. Falling back to standard analysis.")
            security_analysis = analyze_device_security(device_data)
        
        try:
            # Enhanced AI-powered privacy analysis
            privacy_analysis = analyze_privacy_risks_with_ai(device_data)
            logger.info(f"Enhanced AI privacy analysis completed for device {device.name}")
        except Exception as e:
            logger.warning(f"Enhanced AI privacy analysis failed: {e}. Falling back to standard analysis.")
            privacy_analysis = analyze_privacy_risks(device_data)
        
        # Calculate overall scores and risk level
        security_score = security_analysis.get('security_score', 5.0)
        privacy_score = privacy_analysis.get('privacy_score', 5.0)
        overall_score = (security_score + privacy_score) / 2
        
        # Determine risk level based on overall score
        risk_level = 'low'
        if overall_score < 4.0:
            risk_level = 'critical'
        elif overall_score < 5.5:
            risk_level = 'high'
        elif overall_score < 7.0:
            risk_level = 'medium'
        
        # Compile results
        scan_result = {
            'device_id': device.id,
            'scan_time': datetime.utcnow().isoformat(),
            'security_score': security_score,
            'privacy_score': privacy_score,
            'overall_score': overall_score,
            'risk_level': risk_level,
            'vulnerabilities': security_analysis.get('vulnerabilities', []),
            'privacy_issues': privacy_analysis.get('privacy_issues', []),
            'security_analysis_summary': security_analysis.get('analysis_summary', ''),
            'privacy_analysis_summary': privacy_analysis.get('analysis_summary', '')
        }
        
        app.logger.info(f"Scan completed for device {device.name} with score {overall_score}")
        return scan_result
    
    except Exception as e:
        app.logger.error(f"Error during device scan: {str(e)}")
        raise Exception(f"Device scan failed: {str(e)}")


def get_common_vulnerabilities(device_type, manufacturer=None):
    """
    Get common vulnerabilities for a specific device type and manufacturer.
    This is a helper function for the scanner.
    
    Args:
        device_type: Type of device
        manufacturer: Device manufacturer
    
    Returns:
        list: List of common vulnerability templates
    """
    # Base vulnerabilities that apply to most IoT devices
    base_vulnerabilities = [
        {
            "name": "Default Credentials",
            "description": "Device is using default factory credentials which are publicly known.",
            "severity": "critical",
            "base_score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        {
            "name": "Unencrypted Communications",
            "description": "Device transmits data without proper encryption, allowing eavesdropping.",
            "severity": "high",
            "base_score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        },
        {
            "name": "Outdated Firmware",
            "description": "Device is running outdated firmware with known security issues.",
            "severity": "high",
            "base_score": 8.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        },
        {
            "name": "Insecure Web Interface",
            "description": "The device's web interface has multiple security issues including XSS and CSRF vulnerabilities.",
            "severity": "medium",
            "base_score": 6.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"
        },
        {
            "name": "Lack of Firmware Integrity Checks",
            "description": "Device does not verify firmware integrity, allowing potential malicious updates.",
            "severity": "medium",
            "base_score": 5.9,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"
        }
    ]
    
    # Additional vulnerabilities specific to device types could be added in a real implementation
    
    return base_vulnerabilities
