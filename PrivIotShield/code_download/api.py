import json
import uuid
import time
from functools import wraps
from flask import Blueprint, request, jsonify, current_app
from app import db
from models import User, Device, Scan, Vulnerability, PrivacyIssue, Report
from security_scanner import scan_device
from report_generator import generate_report
from datetime import datetime, timedelta

api_bp = Blueprint('api', __name__)

# Simple rate limiting
rate_limits = {}


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({"error": "API key is required"}), 401
        
        user = User.query.filter_by(api_key=api_key).first()
        if not user:
            return jsonify({"error": "Invalid API key"}), 401
        
        # Simple rate limiting - 100 requests per minute
        now = time.time()
        if api_key in rate_limits:
            requests = [t for t in rate_limits[api_key] if now - t < 60]
            rate_limits[api_key] = requests
            
            if len(requests) >= 100:
                return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
        else:
            rate_limits[api_key] = []
        
        rate_limits[api_key].append(now)
        
        # Pass the authenticated user to the view
        return f(user, *args, **kwargs)
    
    return decorated


@api_bp.route('/info', methods=['GET'])
def api_info():
    """API information and documentation"""
    return jsonify({
        "name": "PrivIoT API",
        "version": "1.0",
        "description": "IoT Security Analysis Platform API",
        "documentation": "/api_docs",
        "endpoints": [
            {"path": "/api/info", "method": "GET", "description": "API information"},
            {"path": "/api/devices", "method": "GET", "description": "List devices"},
            {"path": "/api/devices", "method": "POST", "description": "Add device"},
            {"path": "/api/devices/<device_id>", "method": "GET", "description": "Device details"},
            {"path": "/api/scan", "method": "POST", "description": "Start security scan"},
            {"path": "/api/scans", "method": "GET", "description": "List scans"},
            {"path": "/api/scans/<scan_id>", "method": "GET", "description": "Scan details"},
            {"path": "/api/reports", "method": "GET", "description": "List reports"},
            {"path": "/api/reports/<report_id>", "method": "GET", "description": "Report details"},
            {"path": "/api/generate_report", "method": "POST", "description": "Generate report"}
        ]
    })


@api_bp.route('/devices', methods=['GET'])
@require_api_key
def list_devices(user):
    """List all devices for the authenticated user"""
    devices = Device.query.filter_by(user_id=user.id).all()
    
    result = []
    for device in devices:
        # Get the latest scan if it exists
        latest_scan = Scan.query.filter_by(device_id=device.id).order_by(Scan.scan_date.desc()).first()
        
        device_data = {
            "id": device.id,
            "name": device.name,
            "device_type": device.device_type,
            "manufacturer": device.manufacturer,
            "model": device.model,
            "firmware_version": device.firmware_version,
            "ip_address": device.ip_address,
            "mac_address": device.mac_address,
            "location": device.location,
            "created_at": device.created_at.isoformat(),
            "latest_scan": None
        }
        
        if latest_scan:
            device_data["latest_scan"] = {
                "id": latest_scan.id,
                "date": latest_scan.scan_date.isoformat(),
                "status": latest_scan.status,
                "security_score": latest_scan.security_score,
                "privacy_score": latest_scan.privacy_score,
                "overall_score": latest_scan.overall_score,
                "risk_level": latest_scan.risk_level
            }
        
        result.append(device_data)
    
    return jsonify({"devices": result})


@api_bp.route('/devices', methods=['POST'])
@require_api_key
def add_device(user):
    """Add a new device"""
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    required_fields = ['name', 'device_type']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Create new device
    new_device = Device(
        name=data.get('name'),
        device_type=data.get('device_type'),
        manufacturer=data.get('manufacturer'),
        model=data.get('model'),
        firmware_version=data.get('firmware_version'),
        ip_address=data.get('ip_address'),
        mac_address=data.get('mac_address'),
        location=data.get('location'),
        description=data.get('description'),
        user_id=user.id
    )
    
    db.session.add(new_device)
    db.session.commit()
    
    return jsonify({
        "message": "Device added successfully",
        "device": {
            "id": new_device.id,
            "name": new_device.name,
            "device_type": new_device.device_type
        }
    }), 201


@api_bp.route('/devices/<int:device_id>', methods=['GET'])
@require_api_key
def get_device(user, device_id):
    """Get device details"""
    device = Device.query.get_or_404(device_id)
    
    # Check if the device belongs to the authenticated user
    if device.user_id != user.id and user.role != 'admin':
        return jsonify({"error": "You do not have permission to access this device"}), 403
    
    scans = []
    for scan in Scan.query.filter_by(device_id=device.id).order_by(Scan.scan_date.desc()).all():
        scans.append({
            "id": scan.id,
            "date": scan.scan_date.isoformat(),
            "status": scan.status,
            "security_score": scan.security_score,
            "privacy_score": scan.privacy_score,
            "overall_score": scan.overall_score,
            "risk_level": scan.risk_level
        })
    
    return jsonify({
        "device": {
            "id": device.id,
            "name": device.name,
            "device_type": device.device_type,
            "manufacturer": device.manufacturer,
            "model": device.model,
            "firmware_version": device.firmware_version,
            "ip_address": device.ip_address,
            "mac_address": device.mac_address,
            "location": device.location,
            "description": device.description,
            "created_at": device.created_at.isoformat()
        },
        "scans": scans
    })


@api_bp.route('/scan', methods=['POST'])
@require_api_key
def start_scan_api(user):
    """Start a security scan for a device"""
    data = request.get_json()
    
    if not data or 'device_id' not in data:
        return jsonify({"error": "device_id is required"}), 400
    
    device_id = data.get('device_id')
    device = Device.query.get_or_404(device_id)
    
    # Check if the device belongs to the authenticated user
    if device.user_id != user.id and user.role != 'admin':
        return jsonify({"error": "You do not have permission to scan this device"}), 403
    
    # Check if there's already a scan in progress
    in_progress = Scan.query.filter_by(device_id=device.id, status='running').first()
    if in_progress:
        return jsonify({"error": "A scan is already in progress for this device", "scan_id": in_progress.id}), 409
    
    # Create a new scan
    new_scan = Scan(
        device_id=device.id,
        user_id=user.id,
        status='running'
    )
    db.session.add(new_scan)
    db.session.commit()
    
    # Run the scan (in a real app, this would be a background task)
    try:
        scan_result = scan_device(device)
        
        # Update scan with results
        new_scan.status = 'completed'
        new_scan.security_score = scan_result.get('security_score', 0)
        new_scan.privacy_score = scan_result.get('privacy_score', 0)
        new_scan.overall_score = (new_scan.security_score + new_scan.privacy_score) / 2
        new_scan.risk_level = scan_result.get('risk_level', 'medium')
        new_scan.scan_data = json.dumps(scan_result)
        
        # Add vulnerabilities from scan
        for vuln in scan_result.get('vulnerabilities', []):
            vulnerability = Vulnerability(
                name=vuln.get('name', ''),
                description=vuln.get('description', ''),
                severity=vuln.get('severity', 'medium'),
                cvss_score=vuln.get('cvss_score', 0),
                cvss_vector=vuln.get('cvss_vector', ''),
                recommendation=vuln.get('recommendation', ''),
                scan_id=new_scan.id
            )
            db.session.add(vulnerability)
        
        # Add privacy issues from scan
        for issue in scan_result.get('privacy_issues', []):
            privacy_issue = PrivacyIssue(
                name=issue.get('name', ''),
                description=issue.get('description', ''),
                severity=issue.get('severity', 'medium'),
                privacy_impact=issue.get('privacy_impact', 0),
                recommendation=issue.get('recommendation', ''),
                scan_id=new_scan.id
            )
            db.session.add(privacy_issue)
        
        db.session.commit()
        
        return jsonify({
            "message": "Scan completed successfully",
            "scan": {
                "id": new_scan.id,
                "status": new_scan.status,
                "security_score": new_scan.security_score,
                "privacy_score": new_scan.privacy_score,
                "overall_score": new_scan.overall_score,
                "risk_level": new_scan.risk_level
            }
        })
        
    except Exception as e:
        new_scan.status = 'failed'
        db.session.commit()
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500


@api_bp.route('/scans', methods=['GET'])
@require_api_key
def list_scans(user):
    """List all scans for the authenticated user"""
    scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.scan_date.desc()).all()
    
    result = []
    for scan in scans:
        result.append({
            "id": scan.id,
            "device_id": scan.device_id,
            "device_name": scan.device.name,
            "date": scan.scan_date.isoformat(),
            "status": scan.status,
            "security_score": scan.security_score,
            "privacy_score": scan.privacy_score,
            "overall_score": scan.overall_score,
            "risk_level": scan.risk_level
        })
    
    return jsonify({"scans": result})


@api_bp.route('/scans/<int:scan_id>', methods=['GET'])
@require_api_key
def get_scan(user, scan_id):
    """Get scan details"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Check if the scan belongs to the authenticated user
    if scan.user_id != user.id and user.role != 'admin':
        return jsonify({"error": "You do not have permission to access this scan"}), 403
    
    # Get vulnerabilities
    vulnerabilities = []
    for vuln in Vulnerability.query.filter_by(scan_id=scan.id).all():
        vulnerabilities.append({
            "id": vuln.id,
            "name": vuln.name,
            "description": vuln.description,
            "severity": vuln.severity,
            "cvss_score": vuln.cvss_score,
            "cvss_vector": vuln.cvss_vector,
            "status": vuln.status,
            "recommendation": vuln.recommendation
        })
    
    # Get privacy issues
    privacy_issues = []
    for issue in PrivacyIssue.query.filter_by(scan_id=scan.id).all():
        privacy_issues.append({
            "id": issue.id,
            "name": issue.name,
            "description": issue.description,
            "severity": issue.severity,
            "privacy_impact": issue.privacy_impact,
            "status": issue.status,
            "recommendation": issue.recommendation
        })
    
    # Get scan data
    scan_data = scan.get_scan_data()
    
    return jsonify({
        "scan": {
            "id": scan.id,
            "device_id": scan.device_id,
            "device_name": scan.device.name,
            "date": scan.scan_date.isoformat(),
            "status": scan.status,
            "security_score": scan.security_score,
            "privacy_score": scan.privacy_score,
            "overall_score": scan.overall_score,
            "risk_level": scan.risk_level,
            "vulnerabilities": vulnerabilities,
            "privacy_issues": privacy_issues,
            "scan_data": scan_data
        }
    })


@api_bp.route('/reports', methods=['GET'])
@require_api_key
def list_reports(user):
    """List all reports for the authenticated user"""
    reports = Report.query.filter_by(user_id=user.id).order_by(Report.generated_at.desc()).all()
    
    result = []
    for report in reports:
        result.append({
            "id": report.id,
            "title": report.title,
            "report_type": report.report_type,
            "generated_at": report.generated_at.isoformat(),
            "scan_id": report.scan_id,
            "device_id": report.scan.device_id,
            "device_name": report.scan.device.name
        })
    
    return jsonify({"reports": result})


@api_bp.route('/reports/<int:report_id>', methods=['GET'])
@require_api_key
def get_report(user, report_id):
    """Get report details"""
    report = Report.query.get_or_404(report_id)
    
    # Check if the report belongs to the authenticated user
    if report.user_id != user.id and user.role != 'admin':
        return jsonify({"error": "You do not have permission to access this report"}), 403
    
    return jsonify({
        "report": {
            "id": report.id,
            "title": report.title,
            "report_type": report.report_type,
            "generated_at": report.generated_at.isoformat(),
            "scan_id": report.scan_id,
            "device_id": report.scan.device_id,
            "device_name": report.scan.device.name,
            "content": report.content
        }
    })


@api_bp.route('/generate_report', methods=['POST'])
@require_api_key
def generate_report_api(user):
    """Generate a report for a scan"""
    data = request.get_json()
    
    if not data or 'scan_id' not in data:
        return jsonify({"error": "scan_id is required"}), 400
    
    scan_id = data.get('scan_id')
    report_type = data.get('report_type', 'detailed')
    
    if report_type not in ['detailed', 'summary', 'executive']:
        return jsonify({"error": "report_type must be one of: detailed, summary, executive"}), 400
    
    scan = Scan.query.get_or_404(scan_id)
    
    # Check if the scan belongs to the authenticated user
    if scan.user_id != user.id and user.role != 'admin':
        return jsonify({"error": "You do not have permission to generate a report for this scan"}), 403
    
    # Check if scan is completed
    if scan.status != 'completed':
        return jsonify({"error": "Can only generate reports for completed scans"}), 400
    
    # Generate report content
    report_content = generate_report(scan, report_type)
    
    # Create a new report
    title = f"{scan.device.name} Security Report - {datetime.utcnow().strftime('%Y-%m-%d')}"
    new_report = Report(
        title=title,
        report_type=report_type,
        content=report_content,
        scan_id=scan.id,
        user_id=user.id
    )
    db.session.add(new_report)
    db.session.commit()
    
    return jsonify({
        "message": "Report generated successfully",
        "report": {
            "id": new_report.id,
            "title": new_report.title,
            "report_type": new_report.report_type,
            "generated_at": new_report.generated_at.isoformat(),
            "scan_id": new_report.scan_id
        }
    }), 201
