import json
import random
import logging
import time
from datetime import datetime
from app import app
from ai_analyzer import analyze_device_security, analyze_privacy_risks
from cvss_calculator import calculate_cvss_score
from openai_integration import analyze_device_security_with_ai, analyze_privacy_risks_with_ai
from anomaly_detection import detect_anomalies

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
    
    scan_start_time = time.time()
    
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
        
        # Detect anomalies
        anomalies = []
        try:
            anomalies = detect_anomalies(device)
            logger.info(f"Anomaly detection completed: {len(anomalies)} anomalies found")
        except Exception as e:
            logger.warning(f"Anomaly detection failed: {str(e)}")
        
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
        
        # Enhance vulnerabilities with user-friendly information
        enhanced_vulnerabilities = []
        for vuln in security_analysis.get('vulnerabilities', []):
            enhanced_vuln = vuln.copy()
            enhanced_vuln.update({
                'remediation_steps': _generate_user_friendly_steps(vuln.get('name', '')),
                'auto_remediable': _assess_auto_remediation(vuln.get('name', '')),
                'remediation_complexity': _assess_remediation_complexity(vuln.get('severity', 'medium')),
                'estimated_fix_time': _estimate_remediation_time(vuln.get('severity', 'medium')),
                'user_impact': _assess_user_impact(vuln.get('name', ''), device.device_type),
                'business_impact': _assess_business_impact(vuln.get('severity', 'medium'))
            })
            enhanced_vulnerabilities.append(enhanced_vuln)
        
        # Enhance privacy issues with user-friendly information
        enhanced_privacy_issues = []
        for issue in privacy_analysis.get('privacy_issues', []):
            enhanced_issue = issue.copy()
            enhanced_issue.update({
                'user_actions': _generate_privacy_actions(issue.get('name', '')),
                'data_types_affected': _identify_data_types(issue.get('description', '')),
                'compliance_impact': _assess_compliance_impact(issue.get('severity', 'medium')),
                'user_control_level': _assess_user_control(issue.get('name', ''))
            })
            enhanced_privacy_issues.append(enhanced_issue)
        
        # Calculate overall scores and risk level
        security_score = security_analysis.get('security_score', 5.0)
        privacy_score = privacy_analysis.get('privacy_score', 5.0)
        overall_score = (security_score + privacy_score) / 2
        
        # Adjust scores based on anomalies
        if anomalies:
            anomaly_impact = min(2.0, len(anomalies) * 0.5)  # Max 2 point reduction
            security_score = max(0, security_score - anomaly_impact)
            overall_score = (security_score + privacy_score) / 2
        
        # Determine risk level based on overall score
        risk_level = 'low'
        if overall_score < 4.0:
            risk_level = 'critical'
        elif overall_score < 5.5:
            risk_level = 'high'
        elif overall_score < 7.0:
            risk_level = 'medium'
        
        scan_duration = time.time() - scan_start_time
        
        # Compile results
        scan_result = {
            'device_id': device.id,
            'scan_time': datetime.utcnow().isoformat(),
            'scan_duration': scan_duration,
            'security_score': security_score,
            'privacy_score': privacy_score,
            'overall_score': overall_score,
            'risk_level': risk_level,
            'vulnerabilities': enhanced_vulnerabilities,
            'privacy_issues': enhanced_privacy_issues,
            'anomalies': anomalies,
            'security_analysis_summary': security_analysis.get('analysis_summary', ''),
            'privacy_analysis_summary': privacy_analysis.get('analysis_summary', ''),
            'recommendations_summary': security_analysis.get('recommendations_summary', ''),
            'user_control_recommendations': privacy_analysis.get('user_control_recommendations', ''),
            'next_scan_recommended': _calculate_next_scan_date(risk_level),
            'scan_metadata': {
                'scanner_version': '2.0.0',
                'scan_type': 'comprehensive',
                'anomaly_detection_enabled': True
            }
        }
        
        app.logger.info(f"Scan completed for device {device.name} with score {overall_score}")
        return scan_result
    
    except Exception as e:
        app.logger.error(f"Error during device scan: {str(e)}")
        raise Exception(f"Device scan failed: {str(e)}")


def _generate_user_friendly_steps(vulnerability_name):
    """Generate user-friendly remediation steps"""
    name_lower = vulnerability_name.lower()
    
    if 'default' in name_lower and 'credential' in name_lower:
        return [
            "Open your web browser and go to your device's IP address",
            "Log in with the current username and password",
            "Look for 'Settings', 'Security', or 'Users' in the menu",
            "Find the password change option",
            "Create a strong password (at least 12 characters with numbers and symbols)",
            "Save the changes and write down your new password",
            "Test logging in with the new password"
        ]
    elif 'firmware' in name_lower:
        return [
            "Visit your device manufacturer's website",
            "Find the support or downloads section",
            "Search for your device model and download the latest firmware",
            "Access your device's web interface",
            "Look for 'System', 'Administration', or 'Firmware Update'",
            "Upload the firmware file you downloaded",
            "Wait for the update to complete (do not power off the device)",
            "Verify the new firmware version after restart"
        ]
    elif 'encryption' in name_lower or 'ssl' in name_lower:
        return [
            "Access your device's web interface",
            "Navigate to 'Security' or 'Network' settings",
            "Look for SSL/TLS or encryption options",
            "Enable HTTPS and disable HTTP if possible",
            "Choose the strongest encryption available (TLS 1.2 or higher)",
            "Save settings and restart the device if prompted"
        ]
    else:
        return [
            "Review the vulnerability description carefully",
            "Check your device manual or manufacturer's website for guidance",
            "Access your device's settings through its web interface",
            "Look for security-related configuration options",
            "Apply the recommended security settings",
            "Test that your device still works properly after changes"
        ]


def _assess_auto_remediation(vulnerability_name):
    """Assess if vulnerability can be auto-remediated safely"""
    name_lower = vulnerability_name.lower()
    
    # Conservative approach - only simple, safe changes
    safe_auto_fixes = [
        'default credential',
        'weak password',
        'unnecessary service'
    ]
    
    return any(fix in name_lower for fix in safe_auto_fixes)


def _assess_remediation_complexity(severity):
    """Assess complexity from user perspective"""
    complexity_map = {
        'critical': 'high',    # Critical issues often require complex fixes
        'high': 'medium',      # High severity usually needs some technical knowledge
        'medium': 'low',       # Medium issues are often configuration changes
        'low': 'low'          # Low severity issues are typically simple fixes
    }
    return complexity_map.get(severity, 'medium')


def _estimate_remediation_time(severity):
    """Estimate time needed from user perspective"""
    time_map = {
        'critical': '1-3 hours',
        'high': '30-60 minutes', 
        'medium': '15-30 minutes',
        'low': '5-15 minutes'
    }
    return time_map.get(severity, '30 minutes')


def _assess_user_impact(vulnerability_name, device_type):
    """Assess impact on user experience"""
    name_lower = vulnerability_name.lower()
    device_lower = device_type.lower()
    
    if 'credential' in name_lower:
        return "Unauthorized access to your device and personal data"
    elif 'firmware' in name_lower:
        return "Device may be vulnerable to remote attacks and malfunction"
    elif 'encryption' in name_lower:
        return "Your data could be intercepted and read by attackers"
    elif 'camera' in device_lower and any(term in name_lower for term in ['access', 'auth']):
        return "Strangers could view your camera feed"
    elif 'lock' in device_lower:
        return "Your smart lock could be opened by unauthorized persons"
    else:
        return "Device security could be compromised"


def _assess_business_impact(severity):
    """Assess business/organizational impact"""
    impact_map = {
        'critical': 'High risk of data breach, regulatory fines, and business disruption',
        'high': 'Significant security risk that could lead to data compromise',
        'medium': 'Moderate risk that should be addressed to maintain security posture',
        'low': 'Low risk but should be fixed as part of security maintenance'
    }
    return impact_map.get(severity, 'Security risk that should be addressed')


def _generate_privacy_actions(issue_name):
    """Generate user-friendly privacy actions"""
    name_lower = issue_name.lower()
    
    if 'data collection' in name_lower:
        return [
            "Review what data your device collects in its privacy settings",
            "Turn off data collection features you don't need",
            "Check if you can use the device without cloud connectivity"
        ]
    elif 'sharing' in name_lower or 'third party' in name_lower:
        return [
            "Review your device's privacy policy",
            "Check data sharing settings in the device app",
            "Opt out of data sharing where possible",
            "Contact the manufacturer to request data deletion"
        ]
    elif 'tracking' in name_lower:
        return [
            "Turn off location tracking if not needed",
            "Review app permissions on your phone",
            "Use the device in offline mode when possible"
        ]
    else:
        return [
            "Review your device's privacy settings",
            "Read the manufacturer's privacy policy",
            "Adjust settings to your comfort level"
        ]


def _identify_data_types(description):
    """Identify what types of data are affected"""
    data_types = []
    desc_lower = description.lower()
    
    if any(term in desc_lower for term in ['location', 'gps', 'position']):
        data_types.append('location_data')
    if any(term in desc_lower for term in ['voice', 'audio', 'microphone']):
        data_types.append('audio_recordings')
    if any(term in desc_lower for term in ['video', 'camera', 'image']):
        data_types.append('video_recordings')
    if any(term in desc_lower for term in ['usage', 'behavior', 'activity']):
        data_types.append('usage_patterns')
    if any(term in desc_lower for term in ['personal', 'identity']):
        data_types.append('personal_information')
    
    return data_types if data_types else ['device_metadata']


def _assess_compliance_impact(severity):
    """Assess regulatory compliance impact"""
    if severity in ['critical', 'high']:
        return ['GDPR violations possible', 'CCPA compliance risk', 'Potential regulatory fines']
    elif severity == 'medium':
        return ['GDPR transparency requirements', 'CCPA disclosure obligations']
    else:
        return ['Best practice compliance']


def _assess_user_control(issue_name):
    """Assess how much control users have over the privacy issue"""
    name_lower = issue_name.lower()
    
    if any(term in name_lower for term in ['setting', 'option', 'preference']):
        return 'high'  # User can control through settings
    elif any(term in name_lower for term in ['policy', 'sharing', 'collection']):
        return 'medium'  # Some user control available
    else:
        return 'low'  # Limited user control


def _calculate_next_scan_date(risk_level):
    """Calculate when the next scan should be performed"""
    from datetime import timedelta
    
    intervals = {
        'critical': 7,    # Weekly for critical risk
        'high': 14,       # Bi-weekly for high risk
        'medium': 30,     # Monthly for medium risk
        'low': 90         # Quarterly for low risk
    }
    
    days = intervals.get(risk_level, 30)
    next_scan = datetime.utcnow() + timedelta(days=days)
    return next_scan.isoformat()


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