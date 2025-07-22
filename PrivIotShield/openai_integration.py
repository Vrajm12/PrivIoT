import os
import json
import logging
from datetime import datetime
from openai import OpenAI

# Configure logging
logger = logging.getLogger(__name__)

# OpenAI configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
openai = OpenAI(api_key=OPENAI_API_KEY)

# Log initialization status
if OPENAI_API_KEY:
    logger.info("OpenAI client initialized successfully")
else:
    logger.warning("OpenAI API key not found. AI-powered features will be limited.")

def analyze_device_security_with_ai(device_data):
    """
    Use OpenAI to analyze device security based on provided data.
    
    Args:
        device_data (dict): Device information including firmware, model, and other details
    
    Returns:
        dict: Analysis results including vulnerabilities and recommendations
    """
    if not OPENAI_API_KEY:
        logger.warning("OpenAI API key not configured. Using fallback security analysis.")
        return fallback_security_analysis(device_data)
    
    try:
        # Format device data for the prompt
        device_info = json.dumps(device_data, indent=2)
        
        prompt = f"""
        Analyze the security of this IoT device based on its specifications:
        
        Device Information:
        {device_info}
        
        Perform a comprehensive security analysis including:
        1. Known vulnerabilities for this device type, manufacturer, and firmware version
        2. Common attack vectors for this device category
        3. Security assessment on a scale of 1-10
        4. CVSS vectors for any identified vulnerabilities
        5. Specific security recommendations
        
        Format your response as JSON with these fields:
        - vulnerabilities: array of identified vulnerabilities with name, description, severity, and cvss_vector
        - attack_vectors: array of potential attack vectors
        - security_score: numerical score from 1-10
        - recommendations: array of specific security recommendations
        """
        
        response = openai.chat.completions.create(
            model="gpt-4o", # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
            messages=[
                {"role": "system", "content": "You are an IoT security expert analyzing device vulnerability."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        
        result = json.loads(response.choices[0].message.content)
        logger.info(f"AI security analysis completed for device type: {device_data.get('device_type')}")
        return result
        
    except Exception as e:
        logger.error(f"Error in OpenAI security analysis: {str(e)}")
        return fallback_security_analysis(device_data)

def analyze_privacy_risks_with_ai(device_data):
    """
    Use OpenAI to analyze privacy risks based on provided device data.
    
    Args:
        device_data (dict): Device information
    
    Returns:
        dict: Analysis results including privacy issues and recommendations
    """
    if not OPENAI_API_KEY:
        logger.warning("OpenAI API key not configured. Using fallback privacy analysis.")
        return fallback_privacy_analysis(device_data)
    
    try:
        # Format device data for the prompt
        device_info = json.dumps(device_data, indent=2)
        
        prompt = f"""
        Analyze the privacy aspects of this IoT device based on its specifications:
        
        Device Information:
        {device_info}
        
        Perform a comprehensive privacy analysis including:
        1. Data collection capabilities and potential privacy concerns
        2. Known privacy issues for this device type and manufacturer
        3. Privacy impact assessment on a scale of 1-10
        4. Compliance considerations (GDPR, CCPA, etc.)
        5. Privacy-enhancing recommendations
        
        Format your response as JSON with these fields:
        - privacy_issues: array of identified privacy concerns with name, description, and severity
        - data_collection: assessment of data collection practices
        - privacy_score: numerical score from 1-10
        - compliance_gaps: array of potential compliance issues
        - recommendations: array of specific privacy recommendations
        """
        
        response = openai.chat.completions.create(
            model="gpt-4o", # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
            messages=[
                {"role": "system", "content": "You are a privacy expert specializing in IoT devices and data protection."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        
        result = json.loads(response.choices[0].message.content)
        logger.info(f"AI privacy analysis completed for device type: {device_data.get('device_type')}")
        return result
        
    except Exception as e:
        logger.error(f"Error in OpenAI privacy analysis: {str(e)}")
        return fallback_privacy_analysis(device_data)

def generate_security_recommendations_with_ai(vulnerabilities):
    """
    Generate AI-powered recommendations to fix identified vulnerabilities.
    
    Args:
        vulnerabilities (list): List of vulnerability objects
    
    Returns:
        dict: Recommendations for each vulnerability
    """
    if not OPENAI_API_KEY:
        logger.warning("OpenAI API key not configured. Using fallback recommendation generation.")
        return fallback_recommendations(vulnerabilities)
    
    try:
        # Format vulnerabilities for the prompt
        vulns_info = json.dumps(vulnerabilities, indent=2)
        
        prompt = f"""
        Generate detailed security recommendations for these IoT device vulnerabilities:
        
        Vulnerabilities:
        {vulns_info}
        
        For each vulnerability, provide:
        1. Technical mitigation steps
        2. Best practices for remediation
        3. Priority level (critical, high, medium, low)
        4. Estimated effort required to fix
        
        Format your response as JSON with an array of recommendations, each containing:
        - vulnerability_id: ID of the vulnerability being addressed
        - mitigation_steps: array of specific technical steps to fix the issue
        - best_practices: general security best practices relevant to this vulnerability
        - priority: priority level for addressing this vulnerability
        - effort: estimated effort (high, medium, low)
        """
        
        response = openai.chat.completions.create(
            model="gpt-4o", # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
            messages=[
                {"role": "system", "content": "You are an IoT security expert providing actionable recommendations to fix vulnerabilities."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        
        result = json.loads(response.choices[0].message.content)
        logger.info(f"AI recommendations generated for {len(vulnerabilities)} vulnerabilities")
        return result
        
    except Exception as e:
        logger.error(f"Error in OpenAI recommendation generation: {str(e)}")
        return fallback_recommendations(vulnerabilities)

def generate_report_with_ai(scan_data, report_type="detailed"):
    """
    Generate a comprehensive security report using AI based on scan results.
    
    Args:
        scan_data (dict): Scan results and findings
        report_type (str): Type of report (detailed, summary, executive)
    
    Returns:
        str: HTML formatted report content
    """
    if not OPENAI_API_KEY:
        logger.warning("OpenAI API key not configured. Using fallback report generation.")
        return fallback_report_generation(scan_data, report_type)
    
    try:
        # Format scan data for the prompt
        scan_info = json.dumps(scan_data, indent=2)
        
        # Adjust prompt based on report type
        if report_type == "executive":
            audience = "executives and decision-makers"
            detail_level = "high-level strategic insights"
        elif report_type == "summary":
            audience = "security team managers"
            detail_level = "key findings and recommendations without technical details"
        else:  # detailed
            audience = "security analysts and technical teams"
            detail_level = "comprehensive technical details"
        
        prompt = f"""
        Generate a {report_type} security report based on these scan results:
        
        Scan Data:
        {scan_info}
        
        The report should be formatted in HTML and designed for {audience}, providing {detail_level}.
        
        Include these sections:
        1. Executive Summary
        2. Risk Assessment
        3. Key Findings
        4. Technical Details (for detailed reports only)
        5. Recommendations
        6. Next Steps
        
        Make the report visually structured with proper HTML formatting including:
        - Headers (h1, h2, h3)
        - Tables for organized data presentation
        - Lists for findings and recommendations
        - Styled sections with appropriate div elements
        
        For executive and summary reports, include visual elements like charts described in HTML comments.
        """
        
        response = openai.chat.completions.create(
            model="gpt-4o", # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
            messages=[
                {"role": "system", "content": "You are an IoT security expert creating professional security reports."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=4000,
            temperature=0.3
        )
        
        report_html = response.choices[0].message.content
        logger.info(f"AI-generated {report_type} report created successfully")
        return report_html
        
    except Exception as e:
        logger.error(f"Error in OpenAI report generation: {str(e)}")
        return fallback_report_generation(scan_data, report_type)

# Fallback functions when OpenAI is not available

def fallback_security_analysis(device_data):
    """Fallback security analysis when OpenAI is not available"""
    device_type = device_data.get('device_type', '').lower()
    
    # Generic vulnerabilities by device type
    common_vulnerabilities = {
        'camera': [
            {
                'name': 'Default Credentials',
                'description': 'Device may use factory default credentials that are publicly known.',
                'severity': 'high',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            },
            {
                'name': 'Unencrypted Video Stream',
                'description': 'Video stream may be transmitted without encryption.',
                'severity': 'high',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
            }
        ],
        'router': [
            {
                'name': 'Weak Admin Password',
                'description': 'Administrative interface may be secured with weak password.',
                'severity': 'critical',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            },
            {
                'name': 'Outdated Firmware',
                'description': 'Device may be running outdated firmware with known vulnerabilities.',
                'severity': 'high',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            }
        ],
        'smart_speaker': [
            {
                'name': 'Voice Command Injection',
                'description': 'Device may be vulnerable to voice command injection attacks.',
                'severity': 'medium',
                'cvss_vector': 'CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L'
            },
            {
                'name': 'Excessive Data Collection',
                'description': 'Device may collect and transmit more data than necessary.',
                'severity': 'medium',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
            }
        ]
    }
    
    # Generic recommendations
    common_recommendations = [
        "Update firmware to the latest version",
        "Change default passwords to strong, unique passwords",
        "Disable unnecessary services and features",
        "Place device on a separate network segment",
        "Review and modify privacy settings"
    ]
    
    # Find matching device type or use generic
    for key in common_vulnerabilities:
        if key in device_type:
            vulnerabilities = common_vulnerabilities[key]
            security_score = 5  # Medium risk
            break
    else:
        # No specific match, use generic vulnerabilities
        vulnerabilities = [
            {
                'name': 'Unknown Device Security',
                'description': 'Limited information available for security assessment.',
                'severity': 'medium',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            },
            {
                'name': 'Potential Outdated Firmware',
                'description': 'Device may be running outdated firmware with known vulnerabilities.',
                'severity': 'medium',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            }
        ]
        security_score = 4  # Medium-high risk due to uncertainty
    
    return {
        'vulnerabilities': vulnerabilities,
        'attack_vectors': ['Remote Access', 'Default Credentials', 'Firmware Exploitation'],
        'security_score': security_score,
        'recommendations': common_recommendations
    }

def fallback_privacy_analysis(device_data):
    """Fallback privacy analysis when OpenAI is not available"""
    device_type = device_data.get('device_type', '').lower()
    
    # Generic privacy issues by device type
    common_privacy_issues = {
        'camera': [
            {
                'name': 'Visual Privacy Breach',
                'description': 'Device captures video that may include sensitive personal information.',
                'severity': 'high'
            },
            {
                'name': 'Unclear Data Retention',
                'description': 'Unclear policies on how long video footage is stored.',
                'severity': 'medium'
            }
        ],
        'speaker': [
            {
                'name': 'Voice Data Collection',
                'description': 'Device records voice commands which may contain sensitive information.',
                'severity': 'high'
            },
            {
                'name': 'Always-Listening Mode',
                'description': 'Device may constantly listen for wake words, potentially capturing unintended conversations.',
                'severity': 'high'
            }
        ],
        'thermostat': [
            {
                'name': 'Behavior Pattern Analysis',
                'description': 'Device collects data that can reveal home occupancy patterns.',
                'severity': 'medium'
            },
            {
                'name': 'Location Tracking',
                'description': 'Device may track user location to adjust settings.',
                'severity': 'medium'
            }
        ]
    }
    
    # Generic recommendations
    common_recommendations = [
        "Review and minimize data collection settings",
        "Regularly delete stored data",
        "Check if device offers local processing options",
        "Review privacy policy for data sharing practices",
        "Disable features that require excessive data collection"
    ]
    
    # Find matching device type or use generic
    for key in common_privacy_issues:
        if key in device_type:
            privacy_issues = common_privacy_issues[key]
            privacy_score = 4  # Medium-high risk
            break
    else:
        # No specific match, use generic privacy issues
        privacy_issues = [
            {
                'name': 'Unknown Data Collection',
                'description': 'Limited information available about data collection practices.',
                'severity': 'medium'
            },
            {
                'name': 'Potential Data Sharing',
                'description': 'Device may share collected data with third parties.',
                'severity': 'medium'
            }
        ]
        privacy_score = 5  # Medium risk due to uncertainty
    
    return {
        'privacy_issues': privacy_issues,
        'data_collection': 'Potentially excessive for primary functionality',
        'privacy_score': privacy_score,
        'compliance_gaps': ['Potential GDPR consent issues', 'Possible CCPA transparency requirements'],
        'recommendations': common_recommendations
    }

def fallback_recommendations(vulnerabilities):
    """Fallback recommendation generation when OpenAI is not available"""
    recommendations = []
    
    for i, vuln in enumerate(vulnerabilities):
        vuln_id = vuln.get('id', i)
        vuln_name = vuln.get('name', 'Unknown vulnerability')
        vuln_severity = vuln.get('severity', 'medium').lower()
        
        # Set priority based on severity
        if vuln_severity == 'critical':
            priority = 'critical'
            effort = 'high'
        elif vuln_severity == 'high':
            priority = 'high'
            effort = 'medium'
        else:
            priority = 'medium'
            effort = 'low'
        
        # Generic mitigation steps based on common vulnerability types
        mitigation_steps = ["Update firmware to latest version", "Change default credentials", "Disable unnecessary services"]
        
        if 'default' in vuln_name.lower() or 'credential' in vuln_name.lower():
            mitigation_steps = [
                "Change default password to a strong, unique password",
                "Implement multi-factor authentication if available",
                "Restrict administrative access to trusted networks"
            ]
        elif 'firmware' in vuln_name.lower() or 'update' in vuln_name.lower():
            mitigation_steps = [
                "Update device firmware to the latest version",
                "Enable automatic updates if available",
                "Monitor vendor security bulletins for future updates"
            ]
        elif 'encryption' in vuln_name.lower() or 'unencrypted' in vuln_name.lower():
            mitigation_steps = [
                "Enable encryption for all data transmissions",
                "Use HTTPS/TLS for web interfaces",
                "Verify encryption settings are properly configured"
            ]
        
        recommendations.append({
            'vulnerability_id': vuln_id,
            'mitigation_steps': mitigation_steps,
            'best_practices': [
                "Implement network segmentation for IoT devices",
                "Regularly review and update security configurations",
                "Monitor device behavior for anomalies"
            ],
            'priority': priority,
            'effort': effort
        })
    
    return {'recommendations': recommendations}

def fallback_report_generation(scan_data, report_type="detailed"):
    """Fallback report generation when OpenAI is not available"""
    # Extract basic information from scan data
    device_name = scan_data.get('device', {}).get('name', 'Unknown Device')
    device_type = scan_data.get('device', {}).get('device_type', 'Unknown Type')
    scan_date = scan_data.get('scan_date', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
    security_score = scan_data.get('security_score', 5)
    privacy_score = scan_data.get('privacy_score', 5)
    vulnerabilities = scan_data.get('vulnerabilities', [])
    privacy_issues = scan_data.get('privacy_issues', [])
    
    # Determine risk level based on security score
    if security_score >= 8:
        risk_level = "Critical"
        risk_color = "#d9534f"
    elif security_score >= 6:
        risk_level = "High"
        risk_color = "#f0ad4e"
    elif security_score >= 4:
        risk_level = "Medium"
        risk_color = "#5bc0de"
    else:
        risk_level = "Low"
        risk_color = "#5cb85c"
    
    # Generate appropriate report based on type
    if report_type == "executive":
        return generate_executive_fallback_report(device_name, device_type, scan_date, security_score, privacy_score, risk_level, risk_color, len(vulnerabilities), len(privacy_issues))
    elif report_type == "summary":
        return generate_summary_fallback_report(device_name, device_type, scan_date, security_score, privacy_score, risk_level, risk_color, vulnerabilities, privacy_issues)
    else:  # detailed
        return generate_detailed_fallback_report(device_name, device_type, scan_date, security_score, privacy_score, risk_level, risk_color, vulnerabilities, privacy_issues, scan_data)

def generate_executive_fallback_report(device_name, device_type, scan_date, security_score, privacy_score, risk_level, risk_color, vuln_count, privacy_issue_count):
    """Generate executive report without OpenAI"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
            .header {{ background-color: #f0f0f0; padding: 20px; }}
            .risk-badge {{ display: inline-block; padding: 5px 10px; background-color: {risk_color}; color: white; border-radius: 5px; }}
            .section {{ margin-top: 20px; padding: 15px; border-left: 4px solid #ddd; }}
            .summary-box {{ background-color: #f9f9f9; border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Executive Security Report</h1>
            <p>Device: {device_name} ({device_type})</p>
            <p>Scan Date: {scan_date}</p>
            <p>Risk Level: <span class="risk-badge">{risk_level}</span></p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="summary-box">
                <p>This report presents a high-level overview of the security and privacy assessment for {device_name}.</p>
                <p>The device has been identified with <strong>{vuln_count} security vulnerabilities</strong> and <strong>{privacy_issue_count} privacy concerns</strong>.</p>
                <p>Overall risk level is assessed as <strong>{risk_level}</strong> with a security score of <strong>{security_score}/10</strong> and privacy score of <strong>{privacy_score}/10</strong>.</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Key Findings</h2>
            <ul>
                <li>Security Score: {security_score}/10</li>
                <li>Privacy Score: {privacy_score}/10</li>
                <li>Total Vulnerabilities: {vuln_count}</li>
                <li>Total Privacy Issues: {privacy_issue_count}</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                <li>Review detailed report for specific security and privacy issues</li>
                <li>Allocate resources to address {risk_level.lower()} risk findings</li>
                <li>Implement regular security scanning as part of device lifecycle management</li>
                <li>Consider security training for teams handling IoT deployments</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Next Steps</h2>
            <p>Review the detailed security report for comprehensive findings and specific remediation steps.</p>
            <p>Schedule a follow-up scan after implementing recommended security measures.</p>
        </div>
    </body>
    </html>
    """
    return html

def generate_summary_fallback_report(device_name, device_type, scan_date, security_score, privacy_score, risk_level, risk_color, vulnerabilities, privacy_issues):
    """Generate summary report without OpenAI"""
    # Generate vulnerability summary
    vuln_summary = ""
    for i, vuln in enumerate(vulnerabilities[:5]):  # Show top 5
        vuln_summary += f"""
        <tr>
            <td>{i+1}</td>
            <td>{vuln.get('name', 'Unknown')}</td>
            <td>{vuln.get('severity', 'Medium')}</td>
        </tr>
        """
    
    # Generate privacy issues summary
    privacy_summary = ""
    for i, issue in enumerate(privacy_issues[:5]):  # Show top 5
        privacy_summary += f"""
        <tr>
            <td>{i+1}</td>
            <td>{issue.get('name', 'Unknown')}</td>
            <td>{issue.get('severity', 'Medium')}</td>
        </tr>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
            .header {{ background-color: #f0f0f0; padding: 20px; }}
            .risk-badge {{ display: inline-block; padding: 5px 10px; background-color: {risk_color}; color: white; border-radius: 5px; }}
            .section {{ margin-top: 20px; padding: 15px; border-left: 4px solid #ddd; }}
            .summary-box {{ background-color: #f9f9f9; border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            table, th, td {{ border: 1px solid #ddd; }}
            th, td {{ padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Security Assessment Summary</h1>
            <p>Device: {device_name} ({device_type})</p>
            <p>Scan Date: {scan_date}</p>
            <p>Risk Level: <span class="risk-badge">{risk_level}</span></p>
        </div>
        
        <div class="section">
            <h2>Summary</h2>
            <div class="summary-box">
                <p>This summary report provides an overview of key security and privacy findings for {device_name}.</p>
                <p>The assessment identified <strong>{len(vulnerabilities)} security vulnerabilities</strong> and <strong>{len(privacy_issues)} privacy concerns</strong>.</p>
                <p>Overall risk level is assessed as <strong>{risk_level}</strong>.</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Risk Assessment</h2>
            <ul>
                <li>Security Score: <strong>{security_score}/10</strong></li>
                <li>Privacy Score: <strong>{privacy_score}/10</strong></li>
                <li>Combined Risk Level: <strong>{risk_level}</strong></li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Top Security Findings</h2>
            <table>
                <tr>
                    <th>#</th>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                </tr>
                {vuln_summary if vulnerabilities else "<tr><td colspan='3'>No vulnerabilities found</td></tr>"}
            </table>
            {f"<p><em>Only showing top 5 of {len(vulnerabilities)} vulnerabilities</em></p>" if len(vulnerabilities) > 5 else ""}
        </div>
        
        <div class="section">
            <h2>Top Privacy Concerns</h2>
            <table>
                <tr>
                    <th>#</th>
                    <th>Privacy Issue</th>
                    <th>Severity</th>
                </tr>
                {privacy_summary if privacy_issues else "<tr><td colspan='3'>No privacy issues found</td></tr>"}
            </table>
            {f"<p><em>Only showing top 5 of {len(privacy_issues)} privacy issues</em></p>" if len(privacy_issues) > 5 else ""}
        </div>
        
        <div class="section">
            <h2>Key Recommendations</h2>
            <ul>
                <li>Update device firmware to the latest version</li>
                <li>Implement network segmentation to isolate IoT devices</li>
                <li>Review and adjust privacy settings</li>
                <li>Change default credentials and use strong passwords</li>
                <li>Monitor device behavior for suspicious activity</li>
            </ul>
        </div>
    </body>
    </html>
    """
    return html

def generate_detailed_fallback_report(device_name, device_type, scan_date, security_score, privacy_score, risk_level, risk_color, vulnerabilities, privacy_issues, scan_data):
    """Generate detailed report without OpenAI"""
    # Generate detailed vulnerability list
    vuln_details = ""
    for i, vuln in enumerate(vulnerabilities):
        severity = vuln.get('severity', 'Medium')
        severity_color = {
            'Critical': '#d9534f',
            'High': '#f0ad4e',
            'Medium': '#5bc0de',
            'Low': '#5cb85c'
        }.get(severity.capitalize(), '#5bc0de')
        
        vuln_details += f"""
        <div class="finding">
            <h3>{i+1}. {vuln.get('name', 'Unknown Vulnerability')}</h3>
            <p><strong>Severity:</strong> <span style="color: {severity_color};">{severity}</span></p>
            <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
            <p><strong>CVSS:</strong> {vuln.get('cvss_score', 'N/A')} ({vuln.get('cvss_vector', 'N/A')})</p>
            <p><strong>Recommendation:</strong> {vuln.get('recommendation', 'No specific recommendation available')}</p>
        </div>
        """
    
    # Generate detailed privacy issues list
    privacy_details = ""
    for i, issue in enumerate(privacy_issues):
        severity = issue.get('severity', 'Medium')
        severity_color = {
            'Critical': '#d9534f',
            'High': '#f0ad4e',
            'Medium': '#5bc0de',
            'Low': '#5cb85c'
        }.get(severity.capitalize(), '#5bc0de')
        
        privacy_details += f"""
        <div class="finding">
            <h3>{i+1}. {issue.get('name', 'Unknown Privacy Issue')}</h3>
            <p><strong>Severity:</strong> <span style="color: {severity_color};">{severity}</span></p>
            <p><strong>Description:</strong> {issue.get('description', 'No description available')}</p>
            <p><strong>Recommendation:</strong> {issue.get('recommendation', 'No specific recommendation available')}</p>
        </div>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
            .header {{ background-color: #f0f0f0; padding: 20px; }}
            .risk-badge {{ display: inline-block; padding: 5px 10px; background-color: {risk_color}; color: white; border-radius: 5px; }}
            .section {{ margin-top: 20px; padding: 15px; border-left: 4px solid #ddd; }}
            .summary-box {{ background-color: #f9f9f9; border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; }}
            .finding {{ margin-bottom: 25px; padding-bottom: 15px; border-bottom: 1px solid #eee; }}
            table {{ border-collapse: collapse; width: 100%; }}
            table, th, td {{ border: 1px solid #ddd; }}
            th, td {{ padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Detailed Security Assessment Report</h1>
            <p>Device: {device_name} ({device_type})</p>
            <p>Scan Date: {scan_date}</p>
            <p>Risk Level: <span class="risk-badge">{risk_level}</span></p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="summary-box">
                <p>This report provides comprehensive security and privacy analysis for {device_name}.</p>
                <p>The assessment identified <strong>{len(vulnerabilities)} security vulnerabilities</strong> and <strong>{len(privacy_issues)} privacy concerns</strong>.</p>
                <p>Security Score: <strong>{security_score}/10</strong></p>
                <p>Privacy Score: <strong>{privacy_score}/10</strong></p>
                <p>Overall Risk Level: <strong>{risk_level}</strong></p>
            </div>
        </div>
        
        <div class="section">
            <h2>Device Information</h2>
            <table>
                <tr>
                    <th>Attribute</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Name</td>
                    <td>{device_name}</td>
                </tr>
                <tr>
                    <td>Type</td>
                    <td>{device_type}</td>
                </tr>
                <tr>
                    <td>Manufacturer</td>
                    <td>{scan_data.get('device', {}).get('manufacturer', 'Unknown')}</td>
                </tr>
                <tr>
                    <td>Model</td>
                    <td>{scan_data.get('device', {}).get('model', 'Unknown')}</td>
                </tr>
                <tr>
                    <td>Firmware Version</td>
                    <td>{scan_data.get('device', {}).get('firmware_version', 'Unknown')}</td>
                </tr>
                <tr>
                    <td>IP Address</td>
                    <td>{scan_data.get('device', {}).get('ip_address', 'Unknown')}</td>
                </tr>
                <tr>
                    <td>MAC Address</td>
                    <td>{scan_data.get('device', {}).get('mac_address', 'Unknown')}</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Security Vulnerabilities</h2>
            {vuln_details if vulnerabilities else "<p>No security vulnerabilities detected.</p>"}
        </div>
        
        <div class="section">
            <h2>Privacy Issues</h2>
            {privacy_details if privacy_issues else "<p>No privacy issues detected.</p>"}
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <h3>Security Recommendations</h3>
            <ul>
                <li>Update device firmware to the latest version</li>
                <li>Change default credentials and use strong passwords</li>
                <li>Implement network segmentation to isolate IoT devices</li>
                <li>Disable unnecessary services and ports</li>
                <li>Implement a firewall to filter traffic to/from the device</li>
            </ul>
            
            <h3>Privacy Recommendations</h3>
            <ul>
                <li>Review and adjust privacy settings to minimize data collection</li>
                <li>Consider local processing options where available</li>
                <li>Regularly delete stored data</li>
                <li>Review the privacy policy for data sharing practices</li>
                <li>Consider placing sensitive devices on separate networks</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Technical Details</h2>
            <p>Scan performed using PrivIoT Security Scanner v1.0</p>
            <p>Scan duration: {scan_data.get('scan_duration', 'Unknown')}</p>
            <p>Scan status: {scan_data.get('status', 'Completed')}</p>
        </div>
    </body>
    </html>
    """
    return html