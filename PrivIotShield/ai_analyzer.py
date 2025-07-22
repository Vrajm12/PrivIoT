import os
import json
import logging
from openai import OpenAI
from app import app
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

# The newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

# Check if API key is available
if not OPENAI_API_KEY:
    logger.warning("OPENAI_API_KEY not found. AI analysis features will be limited.")
    openai = None
else:
    try:
        openai = OpenAI(api_key=OPENAI_API_KEY)
        logger.info("OpenAI client initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing OpenAI client: {str(e)}")
        openai = None


def analyze_device_security(device_data):
    """
    Use AI to analyze device security based on provided data.
    
    Args:
        device_data (dict): Device information including firmware, model, and other details
    
    Returns:
        dict: Analysis results including vulnerabilities and recommendations
    """
    # Check if OpenAI client is available
    if openai is None:
        logger.warning("OpenAI client not available. Using mock security analysis.")
        return {
            "vulnerabilities": [
                {
                    "name": "Default Credentials",
                    "description": "Device may be using default or weak credentials.",
                    "severity": "high", 
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "recommendation": "Change default passwords and implement strong authentication.",
                    "remediation_steps": [
                        "Access device administration interface",
                        "Navigate to user/password settings",
                        "Change default password to strong, unique password",
                        "Enable two-factor authentication if available",
                        "Document new credentials securely"
                    ],
                    "auto_remediable": False,
                    "remediation_complexity": "low",
                    "estimated_fix_time": "5-10 minutes"
                }
            ],
            "security_score": 5.0,
            "risk_level": "medium",
            "analysis_summary": "This is a simulated security analysis. Please configure a valid OpenAI API key for full AI-powered analysis.",
            "recommendations_summary": "Update device credentials and enable security features to improve overall security posture."
        }
    
    try:
        prompt = f"""
        Analyze the security posture of this IoT device based on the provided information.
        Identify potential vulnerabilities, weaknesses, and security risks.
        
        Device Information:
        - Name: {device_data.get('name', 'Unknown')}
        - Type: {device_data.get('device_type', 'Unknown')}
        - Manufacturer: {device_data.get('manufacturer', 'Unknown')}
        - Model: {device_data.get('model', 'Unknown')}
        - Firmware Version: {device_data.get('firmware_version', 'Unknown')}
        - IP Address: {device_data.get('ip_address', 'Unknown')}
        - MAC Address: {device_data.get('mac_address', 'Unknown')}
        
        Provide a comprehensive security analysis including:
        1. Potential known vulnerabilities for this device/firmware
        2. Common security weaknesses for this type of device
        3. Authentication and encryption concerns
        4. Network security implications
        5. Firmware security analysis
        
        For each vulnerability identified, provide:
        - Name
        - Description
        - Severity (critical, high, medium, low)
        - CVSS Score (0-10)
        - CVSS Vector
        - Recommendation to fix or mitigate
        - Detailed remediation steps (array of step-by-step instructions)
        - Whether it's auto-remediable (true/false)
        - Remediation complexity (low, medium, high)
        - Estimated time to fix (e.g., "5 minutes", "1 hour", "1 day")
        
        Respond with JSON containing these keys:
        - vulnerabilities: array of vulnerability objects
        - security_score: overall security score (0-10)
        - risk_level: overall risk level (critical, high, medium, low)
        - analysis_summary: text summary of the analysis
        - recommendations_summary: brief summary of key recommendations
        - priority_actions: array of top 3 most important actions to take
        """
        
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an IoT security expert who analyzes device security and provides actionable, user-friendly recommendations. Focus on practical steps that users can actually implement."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.4
        )
        
        result = json.loads(response.choices[0].message.content)
        
        # Enhance vulnerabilities with additional metadata
        for vuln in result.get('vulnerabilities', []):
            if 'remediation_steps' not in vuln:
                vuln['remediation_steps'] = _generate_default_remediation_steps(vuln.get('name', ''))
            if 'auto_remediable' not in vuln:
                vuln['auto_remediable'] = _is_auto_remediable(vuln.get('name', ''))
            if 'remediation_complexity' not in vuln:
                vuln['remediation_complexity'] = _assess_complexity(vuln.get('severity', 'medium'))
            if 'estimated_fix_time' not in vuln:
                vuln['estimated_fix_time'] = _estimate_fix_time(vuln.get('remediation_complexity', 'medium'))
        
        return result
    
    except Exception as e:
        app.logger.error(f"Error in AI security analysis: {str(e)}")
        return {
            "vulnerabilities": [],
            "security_score": 5.0,
            "risk_level": "medium",
            "analysis_summary": f"Failed to complete AI security analysis: {str(e)}",
            "recommendations_summary": "Unable to generate recommendations due to analysis failure."
        }


def analyze_privacy_risks(device_data):
    """
    Use AI to analyze privacy risks based on provided device data.
    
    Args:
        device_data (dict): Device information
    
    Returns:
        dict: Analysis results including privacy issues and recommendations
    """
    # Check if OpenAI client is available
    if openai is None:
        logger.warning("OpenAI client not available. Using mock privacy analysis.")
        return {
            "privacy_issues": [
                {
                    "name": "Excessive Data Collection", 
                    "description": "Device may collect more data than necessary for its core functionality.",
                    "severity": "medium",
                    "privacy_impact": 6.5,
                    "recommendation": "Review data collection practices and implement data minimization principles.",
                    "data_types_affected": ["usage_patterns", "device_metadata"],
                    "compliance_impact": ["GDPR Article 5", "CCPA data minimization"],
                    "user_actions": [
                        "Review device privacy settings",
                        "Disable unnecessary data collection features",
                        "Check manufacturer's privacy policy"
                    ]
                }
            ],
            "privacy_score": 5.5,
            "risk_level": "medium",
            "analysis_summary": "This is a simulated privacy analysis. Please configure a valid OpenAI API key for full AI-powered analysis.",
            "user_control_recommendations": "Enable privacy controls and review data sharing settings."
        }
    
    try:
        prompt = f"""
        Analyze the privacy implications of this IoT device based on the provided information.
        Identify potential privacy risks, data collection concerns, and privacy vulnerabilities.
        
        Device Information:
        - Name: {device_data.get('name', 'Unknown')}
        - Type: {device_data.get('device_type', 'Unknown')}
        - Manufacturer: {device_data.get('manufacturer', 'Unknown')}
        - Model: {device_data.get('model', 'Unknown')}
        - Firmware Version: {device_data.get('firmware_version', 'Unknown')}
        - IP Address: {device_data.get('ip_address', 'Unknown')}
        - MAC Address: {device_data.get('mac_address', 'Unknown')}
        
        Provide a comprehensive privacy analysis including:
        1. Types of data likely collected by this device
        2. Potential third-party data sharing
        3. Data retention concerns
        4. User consent and transparency issues
        5. Regulatory compliance concerns (GDPR, CCPA, etc.)
        
        For each privacy issue identified, provide:
        - Name
        - Description
        - Severity (critical, high, medium, low)
        - Privacy Impact Score (0-10)
        - Recommendation to address or mitigate
        - Data types affected (array)
        - Compliance regulations impacted (array)
        - Specific user actions they can take (array)
        
        Respond with JSON containing these keys:
        - privacy_issues: array of privacy issue objects
        - privacy_score: overall privacy score (0-10)
        - risk_level: overall privacy risk level (critical, high, medium, low)
        - analysis_summary: text summary of the analysis
        - user_control_recommendations: summary of actions users can take
        - compliance_status: assessment of regulatory compliance
        """
        
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a privacy expert who analyzes IoT devices for privacy risks and provides user-friendly recommendations for protecting personal data."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.4
        )
        
        result = json.loads(response.choices[0].message.content)
        
        # Enhance privacy issues with user-friendly actions
        for issue in result.get('privacy_issues', []):
            if 'user_actions' not in issue:
                issue['user_actions'] = _generate_privacy_user_actions(issue.get('name', ''))
            if 'data_types_affected' not in issue:
                issue['data_types_affected'] = _identify_affected_data_types(issue.get('description', ''))
        
        return result
    
    except Exception as e:
        app.logger.error(f"Error in AI privacy analysis: {str(e)}")
        return {
            "privacy_issues": [],
            "privacy_score": 5.0,
            "risk_level": "medium",
            "analysis_summary": f"Failed to complete AI privacy analysis: {str(e)}",
            "user_control_recommendations": "Unable to generate privacy recommendations due to analysis failure."
        }


def generate_security_recommendations(vulnerabilities):
    """
    Generate AI-powered recommendations to fix identified vulnerabilities.
    
    Args:
        vulnerabilities (list): List of vulnerability objects
    
    Returns:
        dict: Recommendations for each vulnerability
    """
    # Check if OpenAI client is available
    if openai is None:
        logger.warning("OpenAI client not available. Using mock security recommendations.")
        # Create basic recommendations based on vulnerability names
        recommendations = []
        for vuln in vulnerabilities:
            name = vuln.get("name", "Unknown Vulnerability")
            recommendations.append({
                "vulnerability_name": name,
                "detailed_fix": f"Comprehensive remediation guide for {name}",
                "steps": _generate_default_remediation_steps(name),
                "priority": vuln.get("severity", "medium"),
                "user_friendly_explanation": f"This vulnerability can be fixed by following the provided steps. Estimated time: {_estimate_fix_time(vuln.get('severity', 'medium'))}",
                "tools_needed": ["Device admin access", "Web browser"],
                "difficulty_level": _assess_user_difficulty(name)
            })
        return {"recommendations": recommendations}
    
    try:
        vulnerabilities_json = json.dumps(vulnerabilities)
        
        prompt = f"""
        Generate specific recommendations to fix or mitigate the following security vulnerabilities
        identified in an IoT device:
        
        {vulnerabilities_json}
        
        For each vulnerability, provide:
        1. Detailed step-by-step recommendations for fixing
        2. Configuration changes needed
        3. Additional security controls to implement
        4. Best practices to follow
        5. User-friendly explanation of what the fix accomplishes
        6. Tools or access needed to perform the fix
        7. Difficulty level for average users (beginner, intermediate, advanced)
        8. Alternative solutions if primary fix is not possible
        
        Respond with JSON containing an array of recommendation objects, each with:
        - vulnerability_name: name of the vulnerability
        - detailed_fix: detailed explanation of the fix
        - steps: array of specific steps to take
        - priority: priority of the fix (critical, high, medium, low)
        - user_friendly_explanation: simple explanation for non-technical users
        - tools_needed: array of tools or access required
        - difficulty_level: beginner, intermediate, or advanced
        - alternative_solutions: array of alternative approaches if main fix fails
        """
        
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an IoT security expert providing clear, actionable recommendations that non-technical users can understand and implement. Focus on practical solutions with step-by-step guidance."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        
        result = json.loads(response.choices[0].message.content)
        return result
    
    except Exception as e:
        app.logger.error(f"Error generating security recommendations: {str(e)}")
        return {"recommendations": []}


def _generate_default_remediation_steps(vulnerability_name):
    """Generate default remediation steps based on vulnerability name"""
    name_lower = vulnerability_name.lower()
    
    if 'default' in name_lower and 'credential' in name_lower:
        return [
            "Open your device's web interface in a browser",
            "Log in using current credentials",
            "Navigate to 'Settings' > 'Users' or 'Security'",
            "Change the default password to a strong, unique password",
            "Save the changes and log out",
            "Test login with new credentials"
        ]
    elif 'firmware' in name_lower or 'update' in name_lower:
        return [
            "Visit the manufacturer's support website",
            "Download the latest firmware for your device model",
            "Access your device's administration interface",
            "Navigate to 'System' > 'Firmware Update'",
            "Upload and install the new firmware",
            "Wait for the device to restart and verify the update"
        ]
    elif 'encryption' in name_lower or 'ssl' in name_lower:
        return [
            "Access device settings through web interface",
            "Navigate to 'Security' or 'Network' settings",
            "Enable HTTPS/SSL encryption",
            "Disable weak encryption protocols",
            "Apply settings and restart if required"
        ]
    else:
        return [
            "Review the vulnerability details carefully",
            "Consult device documentation for security settings",
            "Apply recommended security configurations",
            "Test the device functionality after changes",
            "Monitor for any issues or improvements"
        ]


def _is_auto_remediable(vulnerability_name):
    """Determine if a vulnerability can be automatically remediated"""
    name_lower = vulnerability_name.lower()
    
    # Most vulnerabilities require manual intervention for safety
    auto_remediable_types = [
        'default credential',
        'weak password',
        'unnecessary service'
    ]
    
    return any(vuln_type in name_lower for vuln_type in auto_remediable_types)


def _assess_complexity(severity):
    """Assess remediation complexity based on severity"""
    severity_complexity_map = {
        'critical': 'high',
        'high': 'medium',
        'medium': 'medium',
        'low': 'low'
    }
    return severity_complexity_map.get(severity, 'medium')


def _estimate_fix_time(complexity):
    """Estimate time needed to fix based on complexity"""
    time_estimates = {
        'low': '5-15 minutes',
        'medium': '30-60 minutes',
        'high': '1-3 hours'
    }
    return time_estimates.get(complexity, '30-60 minutes')


def _assess_user_difficulty(vulnerability_name):
    """Assess difficulty level for average users"""
    name_lower = vulnerability_name.lower()
    
    if any(term in name_lower for term in ['password', 'credential', 'setting']):
        return 'beginner'
    elif any(term in name_lower for term in ['firmware', 'certificate', 'encryption']):
        return 'intermediate'
    elif any(term in name_lower for term in ['network', 'protocol', 'configuration']):
        return 'advanced'
    else:
        return 'intermediate'


def _generate_privacy_user_actions(issue_name):
    """Generate user-friendly privacy actions"""
    name_lower = issue_name.lower()
    
    if 'data collection' in name_lower:
        return [
            "Review device privacy settings",
            "Disable unnecessary data collection features",
            "Check what data is being shared with third parties"
        ]
    elif 'tracking' in name_lower:
        return [
            "Disable location tracking if not needed",
            "Review tracking permissions",
            "Consider using device in offline mode when possible"
        ]
    else:
        return [
            "Review device privacy policy",
            "Adjust privacy settings to your comfort level",
            "Contact manufacturer for privacy concerns"
        ]


def _identify_affected_data_types(description):
    """Identify data types affected based on description"""
    data_types = []
    description_lower = description.lower()
    
    if any(term in description_lower for term in ['location', 'gps', 'position']):
        data_types.append('location_data')
    if any(term in description_lower for term in ['voice', 'audio', 'microphone']):
        data_types.append('audio_data')
    if any(term in description_lower for term in ['video', 'camera', 'image']):
        data_types.append('video_data')
    if any(term in description_lower for term in ['usage', 'behavior', 'activity']):
        data_types.append('usage_patterns')
    if any(term in description_lower for term in ['personal', 'identity', 'profile']):
        data_types.append('personal_information')
    
    return data_types if data_types else ['device_metadata']