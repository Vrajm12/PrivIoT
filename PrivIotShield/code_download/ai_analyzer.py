import os
import json
from openai import OpenAI
from app import app

# The newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
openai = OpenAI(api_key=OPENAI_API_KEY)


def analyze_device_security(device_data):
    """
    Use AI to analyze device security based on provided data.
    
    Args:
        device_data (dict): Device information including firmware, model, and other details
    
    Returns:
        dict: Analysis results including vulnerabilities and recommendations
    """
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
        
        Respond with JSON containing these keys:
        - vulnerabilities: array of vulnerability objects
        - security_score: overall security score (0-10)
        - risk_level: overall risk level (critical, high, medium, low)
        - analysis_summary: text summary of the analysis
        """
        
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an IoT security expert who analyzes device security and identifies vulnerabilities."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.4
        )
        
        result = json.loads(response.choices[0].message.content)
        return result
    
    except Exception as e:
        app.logger.error(f"Error in AI security analysis: {str(e)}")
        return {
            "vulnerabilities": [],
            "security_score": 5.0,
            "risk_level": "medium",
            "analysis_summary": f"Failed to complete AI security analysis: {str(e)}"
        }


def analyze_privacy_risks(device_data):
    """
    Use AI to analyze privacy risks based on provided device data.
    
    Args:
        device_data (dict): Device information
    
    Returns:
        dict: Analysis results including privacy issues and recommendations
    """
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
        
        Respond with JSON containing these keys:
        - privacy_issues: array of privacy issue objects
        - privacy_score: overall privacy score (0-10)
        - risk_level: overall privacy risk level (critical, high, medium, low)
        - analysis_summary: text summary of the analysis
        """
        
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a privacy expert who analyzes IoT devices for privacy risks and data protection concerns."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.4
        )
        
        result = json.loads(response.choices[0].message.content)
        return result
    
    except Exception as e:
        app.logger.error(f"Error in AI privacy analysis: {str(e)}")
        return {
            "privacy_issues": [],
            "privacy_score": 5.0,
            "risk_level": "medium",
            "analysis_summary": f"Failed to complete AI privacy analysis: {str(e)}"
        }


def generate_security_recommendations(vulnerabilities):
    """
    Generate AI-powered recommendations to fix identified vulnerabilities.
    
    Args:
        vulnerabilities (list): List of vulnerability objects
    
    Returns:
        dict: Recommendations for each vulnerability
    """
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
        
        Respond with JSON containing an array of recommendation objects, each with:
        - vulnerability_name: name of the vulnerability
        - detailed_fix: detailed explanation of the fix
        - steps: array of specific steps to take
        - priority: priority of the fix (critical, high, medium, low)
        """
        
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an IoT security expert providing actionable recommendations to fix security vulnerabilities."},
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
