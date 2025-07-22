import json
from app import app


def analyze_privacy_features(device_data):
    """
    Analyze the privacy features of an IoT device.
    
    Args:
        device_data (dict): Device information
    
    Returns:
        dict: Analysis of privacy features
    """
    device_type = device_data.get('device_type', '').lower()
    
    # Basic privacy features to check for
    privacy_features = {
        'data_encryption': {
            'present': False,
            'strength': 'unknown',
            'description': 'Data encryption protects sensitive information during transmission and storage.'
        },
        'user_consent': {
            'present': False,
            'description': 'Proper user consent mechanisms for data collection and processing.'
        },
        'data_minimization': {
            'present': False,
            'description': 'Collecting only necessary data for device functionality.'
        },
        'privacy_controls': {
            'present': False,
            'description': 'User controls for privacy settings and data collection.'
        },
        'data_retention': {
            'present': False,
            'description': 'Clear policies on how long data is retained.'
        },
        'third_party_sharing': {
            'controlled': False,
            'description': 'Controls on how data is shared with third parties.'
        }
    }
    
    # In a real implementation, this would involve actual device analysis
    # For this demo, we'll make an educated guess based on device type
    
    # Different device types have different typical privacy features
    if 'camera' in device_type or 'webcam' in device_type:
        privacy_features['data_encryption']['present'] = True
        privacy_features['data_encryption']['strength'] = 'medium'
        privacy_features['privacy_controls']['present'] = True
    
    elif 'speaker' in device_type or 'assistant' in device_type:
        privacy_features['user_consent']['present'] = True
        privacy_features['privacy_controls']['present'] = True
    
    elif 'thermostat' in device_type or 'sensor' in device_type:
        privacy_features['data_minimization']['present'] = True
        privacy_features['data_encryption']['present'] = True
        privacy_features['data_encryption']['strength'] = 'low'
    
    return privacy_features


def calculate_privacy_score(privacy_features, privacy_issues):
    """
    Calculate an overall privacy score based on features and issues.
    
    Args:
        privacy_features (dict): Privacy features analysis
        privacy_issues (list): List of privacy issues
    
    Returns:
        float: Privacy score from 0-10
    """
    # Base score starts at 5
    base_score = 5.0
    
    # Add points for good privacy features
    if privacy_features.get('data_encryption', {}).get('present', False):
        encryption_strength = privacy_features.get('data_encryption', {}).get('strength', 'low')
        if encryption_strength == 'high':
            base_score += 1.5
        elif encryption_strength == 'medium':
            base_score += 1.0
        else:
            base_score += 0.5
    
    if privacy_features.get('user_consent', {}).get('present', False):
        base_score += 1.0
    
    if privacy_features.get('data_minimization', {}).get('present', False):
        base_score += 1.0
    
    if privacy_features.get('privacy_controls', {}).get('present', False):
        base_score += 1.0
    
    if privacy_features.get('data_retention', {}).get('present', False):
        base_score += 0.5
    
    if privacy_features.get('third_party_sharing', {}).get('controlled', False):
        base_score += 1.0
    
    # Subtract points for privacy issues
    for issue in privacy_issues:
        severity = issue.get('severity', 'medium').lower()
        
        if severity == 'critical':
            base_score -= 2.0
        elif severity == 'high':
            base_score -= 1.5
        elif severity == 'medium':
            base_score -= 1.0
        elif severity == 'low':
            base_score -= 0.5
    
    # Ensure score is within 0-10 range
    return max(0, min(10, base_score))


def get_common_privacy_issues(device_type):
    """
    Get common privacy issues for a specific device type.
    
    Args:
        device_type: Type of device
    
    Returns:
        list: List of common privacy issue templates
    """
    # Base privacy issues that apply to most IoT devices
    base_issues = [
        {
            "name": "Excessive Data Collection",
            "description": "The device collects more data than necessary for its core functionality.",
            "severity": "medium",
            "privacy_impact": 6.5
        },
        {
            "name": "Unclear Privacy Policy",
            "description": "The device's privacy policy is unclear, incomplete, or difficult to understand.",
            "severity": "medium",
            "privacy_impact": 5.0
        },
        {
            "name": "Third-Party Data Sharing",
            "description": "The device shares user data with third parties without clear user consent.",
            "severity": "high",
            "privacy_impact": 7.5
        },
        {
            "name": "Lack of Data Encryption",
            "description": "User data is not properly encrypted during storage or transmission.",
            "severity": "high",
            "privacy_impact": 8.0
        },
        {
            "name": "Inadequate Access Controls",
            "description": "The device lacks proper access controls for sensitive user data.",
            "severity": "medium",
            "privacy_impact": 6.0
        }
    ]
    
    # Device type specific issues
    type_specific_issues = []
    
    device_type = device_type.lower()
    
    if 'camera' in device_type or 'webcam' in device_type:
        type_specific_issues.append({
            "name": "Continuous Recording Without Indicator",
            "description": "The camera may record without a clear physical indicator showing recording status.",
            "severity": "critical",
            "privacy_impact": 9.0
        })
        
    elif 'speaker' in device_type or 'assistant' in device_type:
        type_specific_issues.append({
            "name": "Always-On Microphone",
            "description": "The device's microphone is always listening, potentially capturing private conversations.",
            "severity": "high",
            "privacy_impact": 8.5
        })
        
    elif 'tracker' in device_type or 'wearable' in device_type:
        type_specific_issues.append({
            "name": "Location Data Collection",
            "description": "The device tracks and stores precise location data that could reveal sensitive information about the user.",
            "severity": "high",
            "privacy_impact": 8.0
        })
    
    return base_issues + type_specific_issues
