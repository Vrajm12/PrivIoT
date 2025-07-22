import math


def calculate_cvss_score(vector_string):
    """
    Calculate CVSS score based on vector string.
    This is a simplified implementation of CVSS v3.1 scoring.
    
    Args:
        vector_string (str): CVSS vector string
    
    Returns:
        float: CVSS score (0-10)
    """
    # Default values
    metrics = {
        # Base metrics
        'AV': 'N',  # Attack Vector: Network
        'AC': 'L',  # Attack Complexity: Low
        'PR': 'N',  # Privileges Required: None
        'UI': 'N',  # User Interaction: None
        'S': 'U',   # Scope: Unchanged
        'C': 'N',   # Confidentiality: None
        'I': 'N',   # Integrity: None
        'A': 'N',   # Availability: None
        
        # Temporal metrics (if provided)
        'E': 'X',   # Exploit Code Maturity: Not Defined
        'RL': 'X',  # Remediation Level: Not Defined
        'RC': 'X'   # Report Confidence: Not Defined
    }
    
    # Parse vector string
    if vector_string and vector_string.startswith('CVSS:'):
        parts = vector_string.split('/')
        for part in parts:
            if ':' in part:
                key, value = part.split(':')
                if key in metrics:
                    metrics[key] = value
    
    # Assign weights based on CVSS v3.1 specification
    weights = {
        # Attack Vector
        'AV': {
            'N': 0.85,  # Network
            'A': 0.62,  # Adjacent
            'L': 0.55,  # Local
            'P': 0.2    # Physical
        },
        # Attack Complexity
        'AC': {
            'L': 0.77,  # Low
            'H': 0.44   # High
        },
        # Privileges Required
        'PR': {
            'N': 0.85,  # None
            'L': 0.62 if metrics['S'] == 'U' else 0.68,  # Low (adjusted for scope)
            'H': 0.27 if metrics['S'] == 'U' else 0.5    # High (adjusted for scope)
        },
        # User Interaction
        'UI': {
            'N': 0.85,  # None
            'R': 0.62   # Required
        },
        # Confidentiality Impact
        'C': {
            'H': 0.56,  # High
            'L': 0.22,  # Low
            'N': 0      # None
        },
        # Integrity Impact
        'I': {
            'H': 0.56,  # High
            'L': 0.22,  # Low
            'N': 0      # None
        },
        # Availability Impact
        'A': {
            'H': 0.56,  # High
            'L': 0.22,  # Low
            'N': 0      # None
        }
    }
    
    # Calculate Exploitability sub-score
    exploitability = 8.22 * weights['AV'][metrics['AV']] * weights['AC'][metrics['AC']] * \
                   weights['PR'][metrics['PR']] * weights['UI'][metrics['UI']]
    
    # Calculate Impact sub-score
    impact_base = 1 - ((1 - weights['C'][metrics['C']]) * (1 - weights['I'][metrics['I']]) * (1 - weights['A'][metrics['A']]))
    
    if metrics['S'] == 'U':  # Scope: Unchanged
        impact = 6.42 * impact_base
    else:  # Scope: Changed
        impact = 7.52 * (impact_base - 0.029) - 3.25 * pow(impact_base - 0.02, 15)
    
    # Calculate Base Score
    if impact <= 0:
        base_score = 0
    elif metrics['S'] == 'U':  # Scope: Unchanged
        base_score = min(exploitability + impact, 10)
    else:  # Scope: Changed
        base_score = min(1.08 * (exploitability + impact), 10)
    
    # Round up to 1 decimal place
    return round(base_score * 10) / 10


def get_risk_level(cvss_score):
    """
    Determine risk level based on CVSS score.
    
    Args:
        cvss_score (float): CVSS score
    
    Returns:
        str: Risk level (critical, high, medium, low, none)
    """
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    elif cvss_score > 0.0:
        return "low"
    else:
        return "none"


def parse_cvss_vector(vector_string):
    """
    Parse CVSS vector string into human-readable description.
    
    Args:
        vector_string (str): CVSS vector string
    
    Returns:
        dict: CVSS metrics in human-readable format
    """
    if not vector_string or not vector_string.startswith('CVSS:'):
        return {"error": "Invalid CVSS vector string"}
    
    # Definitions for each metric
    metrics_def = {
        'AV': {
            'name': 'Attack Vector',
            'N': 'Network',
            'A': 'Adjacent Network',
            'L': 'Local',
            'P': 'Physical'
        },
        'AC': {
            'name': 'Attack Complexity',
            'L': 'Low',
            'H': 'High'
        },
        'PR': {
            'name': 'Privileges Required',
            'N': 'None',
            'L': 'Low',
            'H': 'High'
        },
        'UI': {
            'name': 'User Interaction',
            'N': 'None',
            'R': 'Required'
        },
        'S': {
            'name': 'Scope',
            'U': 'Unchanged',
            'C': 'Changed'
        },
        'C': {
            'name': 'Confidentiality Impact',
            'H': 'High',
            'L': 'Low',
            'N': 'None'
        },
        'I': {
            'name': 'Integrity Impact',
            'H': 'High',
            'L': 'Low',
            'N': 'None'
        },
        'A': {
            'name': 'Availability Impact',
            'H': 'High',
            'L': 'Low',
            'N': 'None'
        },
        'E': {
            'name': 'Exploit Code Maturity',
            'X': 'Not Defined',
            'H': 'High',
            'F': 'Functional',
            'P': 'Proof-of-Concept',
            'U': 'Unproven'
        },
        'RL': {
            'name': 'Remediation Level',
            'X': 'Not Defined',
            'U': 'Unavailable',
            'W': 'Workaround',
            'T': 'Temporary Fix',
            'O': 'Official Fix'
        },
        'RC': {
            'name': 'Report Confidence',
            'X': 'Not Defined',
            'C': 'Confirmed',
            'R': 'Reasonable',
            'U': 'Unknown'
        }
    }
    
    result = {'vector': vector_string, 'metrics': {}}
    
    # Parse vector string
    parts = vector_string.split('/')
    for part in parts:
        if ':' in part:
            key, value = part.split(':')
            if key in metrics_def:
                metric_name = metrics_def[key]['name']
                metric_value = metrics_def[key].get(value, 'Unknown')
                result['metrics'][metric_name] = metric_value
    
    return result
