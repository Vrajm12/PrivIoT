import json
import uuid
import time
import logging
from functools import wraps
from flask import Blueprint, request, jsonify, current_app
from extensions import db
from models import User, Device, Scan, Vulnerability, PrivacyIssue, Report, Asset, AssetService, RiskAssessment, ContainmentIntent, AuditEvent, ScanJob
from security_scanner import scan_device
from report_generator import generate_report
from vuln_intel import vuln_engine
from compliance_engine import compliance_engine
from remediation_engine import remediation_engine
from deep_discovery import discovery_engine
from traffic_auditor import traffic_auditor
from security_pipeline import security_pipeline
from containment_engine import containment_engine
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

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


# ==============================================================================
# PrivIoT API v2 - Production Threat Intelligence & Compliance Endpoints
# ==============================================================================

@api_bp.route('/v2/intelligence/lookup', methods=['POST'])
@require_api_key
def api_v2_intelligence_lookup(user):
    """
    Look up authoritative CVEs, CISA KEV status, and EPSS metrics for arbitrary device data.
    """
    data = request.get_json() or {}
    vulnerabilities = vuln_engine.match_vulnerabilities(data)
    risk_profile = vuln_engine.calculate_device_risk_profile(vulnerabilities)
    return jsonify({
        "status": "success",
        "device_query": data,
        "risk_profile": risk_profile,
        "vulnerabilities": vulnerabilities
    })


@api_bp.route('/v2/compliance/audit', methods=['POST'])
@require_api_key
def api_v2_compliance_audit(user):
    """
    Perform formal ETSI EN 303 645, NIST IR 8259A, and OWASP IoT Top 10 compliance audit.
    """
    data = request.get_json() or {}
    device_data = data.get("device", data)
    vulnerabilities = data.get("vulnerabilities")
    if vulnerabilities is None:
        vulnerabilities = vuln_engine.match_vulnerabilities(device_data)
    
    audit_results = compliance_engine.comprehensive_audit(device_data, vulnerabilities)
    return jsonify({
        "status": "success",
        "compliance_audit": audit_results
    })


@api_bp.route('/v2/remediation/firewall-rules', methods=['POST'])
@require_api_key
def api_v2_firewall_rules(user):
    """
    Generate production firewall isolation scripts and DNS sinkhole rules.
    """
    data = request.get_json() or {}
    ip = data.get("ip_address", "192.168.1.100")
    mac = data.get("mac_address")
    vendor = data.get("manufacturer", "")
    name = data.get("name", "IoT Device")

    return jsonify({
        "status": "success",
        "ip_address": ip,
        "mac_address": mac,
        "rules": {
            "iptables": remediation_engine.generate_iptables_rules(ip, mac),
            "nftables": remediation_engine.generate_nftables_rules(ip, mac),
            "pfsense": remediation_engine.generate_pfsense_rules(ip, name),
            "unifi": remediation_engine.generate_unifi_cli_rules(ip, mac),
            "mikrotik": remediation_engine.generate_mikrotik_script(ip, name),
            "dns_sinkhole": remediation_engine.generate_dns_sinkhole_blocklist(vendor)
        }
    })


@api_bp.route('/v2/discovery/deep-probe', methods=['POST'])
@require_api_key
def api_v2_deep_probe(user):
    """
    Actively probe a device IP for open IoT services, banners, and UPnP descriptors.
    """
    data = request.get_json() or {}
    ip = data.get("ip_address")
    if not ip:
        return jsonify({"error": "ip_address is required"}), 400

    timeout = float(data.get("timeout", 1.5))
    probe_results = discovery_engine.probe_device_services(ip, timeout=timeout)
    return jsonify({
        "status": "success",
        "results": probe_results
    })


@api_bp.route('/v2/traffic/audit-payload', methods=['POST'])
@require_api_key
def api_v2_audit_payload(user):
    """
    Inspect raw network packet payload for cleartext credentials, PII, and serial leaks.
    """
    data = request.get_json() or {}
    raw_payload = data.get("payload", "")
    protocol = data.get("protocol", "HTTP")
    src_ip = data.get("src_ip", "192.168.1.50")
    
    audit_res = traffic_auditor.audit_payload(raw_payload, protocol=protocol, src_ip=src_ip)
    return jsonify({
        "status": "success",
        "audit": audit_res
    })


@api_bp.route('/v2/traffic/audit-dns', methods=['POST'])
@require_api_key
def api_v2_audit_dns(user):
    """
    Audit DNS queries to detect unauthorized telemetry destinations and cloud relays.
    """
    data = request.get_json() or {}
    domains = data.get("domains", [])
    device_name = data.get("device_name", "IoT Device")

    audit_res = traffic_auditor.audit_dns_traffic(domains, device_name=device_name)
    return jsonify({
        "status": "success",
        "audit": audit_res
    })


# ==============================================================================
# Phase 1: Canonical Scans, Assets, Containment & Audit Trail REST APIs
# ==============================================================================

@api_bp.route('/v2/scans', methods=['POST'])
@require_api_key
def api_v2_create_scan(user):
    """
    Trigger safe discovery and exposure scan on an authorized subnet.
    """
    data = request.get_json() or {}
    target_scope = data.get("target_scope")
    if not target_scope:
        return jsonify({"error": "target_scope is required (e.g. '192.168.1.0/24')"}), 400

    profile = data.get("profile", "safe")
    rate_limit = int(data.get("rate_limit", 50))
    concurrency = int(data.get("concurrency", 10))
    timeout = float(data.get("timeout", 1.0))
    allow_loopback = bool(data.get("allow_loopback", False) and current_app.config.get('TESTING', False))

    try:
        scan_res = security_pipeline.execute_subnet_exposure_scan(
            user_id=user.id,
            target_scope=target_scope,
            profile=profile,
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=timeout,
            allow_loopback=allow_loopback
        )
        return jsonify({
            "status": "success",
            "scan": scan_res
        }), 201
    except ValueError as ve:
        return jsonify({"error": f"Invalid scan parameters: {str(ve)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500


@api_bp.route('/v2/scans/<scan_id>', methods=['GET'])
@require_api_key
def api_v2_get_scan(user, scan_id):
    """
    Get scan job status and summary.
    """
    job = ScanJob.query.filter_by(scan_uuid=scan_id, user_id=user.id).first()
    if not job:
        return jsonify({"error": "Scan job not found"}), 404
    return jsonify({
        "status": "success",
        "scan": job.to_dict()
    })


@api_bp.route('/v2/scans/<scan_id>/cancel', methods=['POST'])
@require_api_key
def api_v2_cancel_scan(user, scan_id):
    """
    Cancel an active scan job.
    """
    job = ScanJob.query.filter_by(scan_uuid=scan_id, user_id=user.id).first()
    if not job:
        return jsonify({"error": "Scan job not found"}), 404
    
    if job.status == 'running':
        job.status = 'cancelled'
        job.end_time = datetime.utcnow()
        db.session.commit()

        audit = AuditEvent(
            actor_id=user.id,
            action='scan_cancelled',
            target_type='scan',
            target_id=job.scan_uuid,
            details_json=json.dumps({"cancelled_at": job.end_time.isoformat()}),
            result='success'
        )
        db.session.add(audit)
        db.session.commit()

    return jsonify({
        "status": "success",
        "message": f"Scan {scan_id} cancelled",
        "scan": job.to_dict()
    })


@api_bp.route('/v2/assets', methods=['GET'])
@require_api_key
def api_v2_list_assets(user):
    """
    List reconciled canonical Assets with pagination and filtering.
    """
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 20)), 100)
    vendor_filter = request.args.get('vendor')
    type_filter = request.args.get('device_type')

    query = Asset.query.filter_by(user_id=user.id)
    if vendor_filter:
        query = query.filter(Asset.vendor.ilike(f"%{vendor_filter}%"))
    if type_filter:
        query = query.filter(Asset.device_type.ilike(f"%{type_filter}%"))

    total = query.count()
    assets = query.order_by(Asset.last_seen.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "status": "success",
        "total": total,
        "page": page,
        "per_page": per_page,
        "assets": [a.to_dict() for a in assets]
    })


@api_bp.route('/v2/assets/<int:asset_id>', methods=['GET'])
@require_api_key
def api_v2_get_asset(user, asset_id):
    """
    Get detailed Device Trust Profile for a specific Asset.
    """
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404
    
    latest_risk = asset.get_latest_risk()
    active_containment = asset.get_active_containment()

    return jsonify({
        "status": "success",
        "asset": asset.to_dict(),
        "services": [s.to_dict() for s in asset.services.all()],
        "latest_risk": latest_risk.to_dict() if latest_risk else None,
        "active_containment": active_containment.to_dict() if active_containment else None
    })


@api_bp.route('/v2/assets/<int:asset_id>/services', methods=['GET'])
@require_api_key
def api_v2_get_asset_services(user, asset_id):
    """
    List open ports, protocols, and services for an Asset.
    """
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    return jsonify({
        "status": "success",
        "asset_id": asset_id,
        "services": [s.to_dict() for s in asset.services.all()]
    })


@api_bp.route('/v2/assets/<int:asset_id>/vulnerabilities', methods=['GET'])
@require_api_key
def api_v2_get_asset_vulnerabilities(user, asset_id):
    """
    Get authoritative vulnerability matches with CISA KEV and EPSS intelligence.
    """
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    service_names = [s.service_name for s in asset.services.all()]
    open_ports = [s.port for s in asset.services.all()]
    device_dict = {
        "manufacturer": asset.vendor or asset.manufacturer,
        "model": asset.model,
        "firmware_version": asset.firmware_version,
        "device_type": asset.device_type,
        "open_ports": open_ports,
        "services": service_names
    }
    vulns = vuln_engine.get_vulnerabilities_for_device(device_dict)

    return jsonify({
        "status": "success",
        "asset_id": asset_id,
        "total_vulnerabilities": len(vulns),
        "vulnerabilities": vulns
    })


@api_bp.route('/v2/assets/<int:asset_id>/risk', methods=['GET'])
@require_api_key
def api_v2_get_asset_risk(user, asset_id):
    """
    Get full explainable PrivIoT Risk Index (PRI) breakdown for an Asset.
    """
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    latest_risk = asset.get_latest_risk()
    if not latest_risk:
        return jsonify({"error": "No risk assessment available for this asset"}), 404

    return jsonify({
        "status": "success",
        "asset_id": asset_id,
        "risk_assessment": latest_risk.to_dict()
    })


@api_bp.route('/v2/assets/<int:asset_id>/containment/preview', methods=['POST'])
@require_api_key
def api_v2_preview_containment(user, asset_id):
    """
    Generate Safe Impact Preview for isolating an Asset on a target gateway.
    """
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    data = request.get_json() or {}
    provider = data.get("provider", "pfsense")

    latest_risk = asset.get_latest_risk()
    pri_data = latest_risk.to_dict() if latest_risk else {"pri_score": 7.0, "pri_level": "high"}
    
    intent = containment_engine.create_intent_for_asset(asset, pri_data)
    try:
        preview = containment_engine.preview_containment(intent, asset.ip_address, provider_name=provider)
        
        # Log preview audit event
        audit = AuditEvent(
            actor_id=user.id,
            action='containment_previewed',
            target_type='asset',
            target_id=str(asset_id),
            details_json=json.dumps({"provider": provider, "ip": asset.ip_address}),
            result='success'
        )
        db.session.add(audit)
        db.session.commit()

        return jsonify({
            "status": "success",
            "preview": preview
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400


@api_bp.route('/v2/assets/<int:asset_id>/containment/generate', methods=['POST'])
@require_api_key
def api_v2_generate_containment(user, asset_id):
    """
    Generate provider-specific firewall rules and rollback policy.
    """
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    data = request.get_json() or {}
    provider = data.get("provider", "pfsense")

    latest_risk = asset.get_latest_risk()
    pri_data = latest_risk.to_dict() if latest_risk else {"pri_score": 7.0, "pri_level": "high"}
    
    intent = containment_engine.create_intent_for_asset(asset, pri_data)
    try:
        policies = containment_engine.generate_provider_policy(intent, asset.ip_address, mac_address=asset.mac_address, provider_name=provider)
        return jsonify({
            "status": "success",
            "provider": provider,
            "ip_address": asset.ip_address,
            "mac_address": asset.mac_address,
            "apply_policy": policies["apply_policy"],
            "rollback_policy": policies["rollback_policy"]
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400


@api_bp.route('/v2/assets/<int:asset_id>/containment/approve', methods=['POST'])
@require_api_key
def api_v2_approve_containment(user, asset_id):
    """
    Human Approval for containment policy. Transitions status to 'approved' and records audit event.
    """
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    data = request.get_json() or {}
    provider = data.get("provider", "pfsense")

    intent = asset.get_active_containment()
    if not intent:
        # Create one
        latest_risk = asset.get_latest_risk()
        pri_data = latest_risk.to_dict() if latest_risk else {"pri_score": 7.0, "pri_level": "high"}
        intent_data = containment_engine.create_intent_for_asset(asset, pri_data)
        policies = containment_engine.generate_provider_policy(intent_data, asset.ip_address, provider_name=provider)
        
        intent = ContainmentIntent(
            asset_id=asset.id,
            reason=intent_data["reason"],
            severity=intent_data["severity"],
            desired_effect=intent_data["desired_effect"],
            allowed_destinations=json.dumps(intent_data["allowed_destinations"]),
            blocked_destinations=json.dumps(intent_data["blocked_destinations"]),
            allowed_ports=json.dumps(intent_data["allowed_ports"]),
            blocked_ports=json.dumps(intent_data["blocked_ports"]),
            protocol=intent_data["protocol"],
            status="approved",
            approved_by_id=user.id,
            applied_provider=provider,
            generated_policy=policies["apply_policy"],
            rollback_policy=policies["rollback_policy"]
        )
        db.session.add(intent)
    else:
        intent.status = "approved"
        intent.approved_by_id = user.id
        intent.applied_provider = provider

    audit = AuditEvent(
        actor_id=user.id,
        action='containment_approved',
        target_type='containment',
        target_id=str(intent.id or asset.id),
        details_json=json.dumps({"asset_id": asset.id, "ip": asset.ip_address, "provider": provider}),
        result='success'
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": f"Containment policy approved for asset {asset.id} ({asset.ip_address})",
        "containment": intent.to_dict()
    })


@api_bp.route('/v2/assets/<int:asset_id>/containment/rollback', methods=['POST'])
@require_api_key
def api_v2_rollback_containment(user, asset_id):
    """
    Execute 1-Click Rollback for containment policy.
    """
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    intent = asset.get_active_containment()
    if not intent:
        return jsonify({"error": "No active containment policy found for this asset"}), 404

    intent.status = "rolled_back"

    audit = AuditEvent(
        actor_id=user.id,
        action='containment_rolled_back',
        target_type='containment',
        target_id=str(intent.id),
        details_json=json.dumps({"asset_id": asset.id, "ip": asset.ip_address, "provider": intent.applied_provider}),
        result='success'
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": f"Containment rolled back for asset {asset.id} ({asset.ip_address})",
        "rollback_script": intent.rollback_policy,
        "containment": intent.to_dict()
    })


@api_bp.route('/v2/audit-logs', methods=['GET'])
@require_api_key
def api_v2_get_audit_logs(user):
    """
    Query immutable audit trail for security and operational compliance with tenant boundaries.
    """
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 50)), 200)

    query = AuditEvent.query.filter_by(tenant_id=tenant_id).filter((AuditEvent.actor_id == user.id) | (AuditEvent.actor_id == None))
    total = query.count()
    events = query.order_by(AuditEvent.timestamp.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "status": "success",
        "tenant_id": tenant_id,
        "total": total,
        "page": page,
        "per_page": per_page,
        "events": [e.to_dict() for e in events]
    })


@api_bp.route('/v2/threat-intel/health', methods=['GET'])
@require_api_key
def api_v2_threat_intel_health(user):
    """
    Expose authoritative threat feed freshness, NVD, CISA KEV, and EPSS synchronization status.
    """
    return jsonify({
        "status": "success",
        "threat_intel_health": vuln_engine.get_feed_health()
    })


# ==============================================================================
# Phase 2: Telemetry Ingestion, Collectors, Trust Profile, Alerts & Verification
# ==============================================================================

@api_bp.route('/v2/collectors/register', methods=['POST'])
@require_api_key
def api_v2_register_collector(user):
    """
    Register a new telemetry sensor node.
    """
    from telemetry_engine import telemetry_engine
    data = request.get_json() or {}
    name = data.get("name")
    if not name:
        return jsonify({"error": "Collector name is required"}), 400

    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    site_id = data.get("site_id", "default_site")
    collector_type = data.get("collector_type", "passive_packet")
    network_scope = data.get("network_scope", "192.168.1.0/24")

    collector, raw_token = telemetry_engine.register_collector(
        tenant_id=tenant_id,
        site_id=site_id,
        name=name,
        collector_type=collector_type,
        network_scope=network_scope
    )

    return jsonify({
        "status": "success",
        "message": "Collector registered successfully. Save the token securely; it will not be shown again.",
        "collector": collector.to_dict(),
        "sensor_token": raw_token
    }), 201


@api_bp.route('/v2/collectors', methods=['GET'])
@require_api_key
def api_v2_list_collectors(user):
    """
    List registered telemetry sensors for the tenant.
    """
    from models import Collector
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    collectors = Collector.query.filter_by(tenant_id=tenant_id).all()
    return jsonify({
        "status": "success",
        "collectors": [c.to_dict() for c in collectors]
    })


@api_bp.route('/v2/telemetry/ingest', methods=['POST'])
def api_v2_ingest_telemetry():
    """
    Ingest a batch of telemetry observations from an authenticated collector.
    """
    from telemetry_engine import telemetry_engine
    sensor_token = request.headers.get("X-Sensor-Token")
    if not sensor_token:
        return jsonify({"error": "Missing X-Sensor-Token header"}), 401

    collector = telemetry_engine.authenticate_collector(sensor_token)
    if not collector:
        return jsonify({"error": "Invalid or revoked sensor token"}), 403

    raw_events = request.get_json()
    if not isinstance(raw_events, list):
        return jsonify({"error": "Payload must be a JSON array of events"}), 400

    try:
        res = telemetry_engine.ingest_telemetry_batch(collector, raw_events)
        return jsonify(res), 200
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        logger.error(f"Telemetry ingestion error: {e}")
        return jsonify({"error": f"Internal ingestion failure: {str(e)}"}), 500


@api_bp.route('/v2/assets/<int:asset_id>/trust-profile', methods=['GET'])
@require_api_key
def api_v2_get_trust_profile(user, asset_id):
    """
    Fetch canonical Device Trust Profile for an Asset.
    """
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    return jsonify({
        "status": "success",
        "trust_profile": asset.get_trust_profile()
    })


@api_bp.route('/v2/assets/<int:asset_id>/baseline', methods=['GET'])
@require_api_key
def api_v2_get_asset_baseline(user, asset_id):
    """
    Fetch Synthetic MUD baseline and active drift records for an Asset.
    """
    from models import BehavioralBaseline, BehavioralDriftEvent
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    baseline = BehavioralBaseline.query.filter_by(tenant_id=tenant_id, asset_id=asset.id).first()
    drifts = BehavioralDriftEvent.query.filter_by(tenant_id=tenant_id, asset_id=asset.id).order_by(BehavioralDriftEvent.created_at.desc()).all()

    return jsonify({
        "status": "success",
        "asset_id": asset.id,
        "baseline": baseline.to_dict() if baseline else None,
        "drifts": [d.to_dict() for d in drifts]
    })


@api_bp.route('/v2/alerts', methods=['GET'])
@require_api_key
def api_v2_list_alerts(user):
    """
    List deterministic security and operational alerts.
    """
    from models import Alert
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    status_filter = request.args.get("status")
    severity_filter = request.args.get("severity")

    query = Alert.query.filter_by(tenant_id=tenant_id)
    if status_filter:
        query = query.filter_by(status=status_filter.upper())
    if severity_filter:
        query = query.filter_by(severity=severity_filter.lower())

    alerts = query.order_by(Alert.created_at.desc()).limit(100).all()
    return jsonify({
        "status": "success",
        "total": len(alerts),
        "alerts": [a.to_dict() for a in alerts]
    })


@api_bp.route('/v2/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@require_api_key
def api_v2_acknowledge_alert(user, alert_id):
    from alert_engine import alert_engine
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    try:
        alert = alert_engine.acknowledge_alert(alert_id, user.id, tenant_id)
        return jsonify({"status": "success", "alert": alert.to_dict()})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404


@api_bp.route('/v2/alerts/<int:alert_id>/resolve', methods=['POST'])
@require_api_key
def api_v2_resolve_alert(user, alert_id):
    from alert_engine import alert_engine
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    try:
        alert = alert_engine.resolve_alert(alert_id, user.id, tenant_id)
        return jsonify({"status": "success", "alert": alert.to_dict()})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404


@api_bp.route('/v2/assets/<int:asset_id>/containment/apply', methods=['POST'])
@require_api_key
def api_v2_apply_containment(user, asset_id):
    """
    Execute programmatic containment push to the configured firewall provider.
    Transitions intent state: APPROVED -> APPLYING -> APPLIED_UNVERIFIED / VERIFIED.
    """
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    intent = asset.get_active_containment()
    if not intent:
        return jsonify({"error": "No active approved containment policy to apply"}), 400

    try:
        intent.status = containment_engine.transition_state(intent.status, "APPLYING")
        res = containment_engine.execute_apply(intent.to_dict(), asset.ip_address, provider_name=intent.applied_provider or "pfsense")
        
        # Verify immediately
        verified, vmsg = containment_engine.execute_verify(intent.to_dict(), asset.ip_address, provider_name=intent.applied_provider or "pfsense")
        
        if verified:
            intent.status = containment_engine.transition_state("APPLYING", "VERIFIED")
        else:
            intent.status = containment_engine.transition_state("APPLYING", "APPLIED_UNVERIFIED")

        audit = AuditEvent(
            tenant_id=tenant_id,
            actor_id=user.id,
            action='containment_applied',
            target_type='containment',
            target_id=str(intent.id),
            details_json=json.dumps({"provider": intent.applied_provider, "status": intent.status, "verification": vmsg}),
            result='success'
        )
        db.session.add(audit)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": f"Containment policy pushed to {intent.applied_provider}",
            "containment": intent.to_dict(),
            "verification": vmsg
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400


@api_bp.route('/v2/assets/<int:asset_id>/containment/verify', methods=['POST'])
@api_bp.route('/v2/assets/<int:asset_id>/verify', methods=['POST'])
@require_api_key
def api_v2_verify_containment_endpoint(user, asset_id):
    """
    Verify live firewall state for applied containment policy.
    """
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    intent = asset.get_active_containment()
    if not intent:
        return jsonify({"error": "No active containment policy to verify"}), 404

    verified, vmsg = containment_engine.execute_verify(intent.to_dict(), asset.ip_address, provider_name=intent.applied_provider or "pfsense")
    
    if verified:
        intent.status = "VERIFIED"
    else:
        intent.status = "APPLIED_UNVERIFIED"
    db.session.commit()

    return jsonify({
        "status": "success",
        "verified": verified,
        "verification_status": intent.status,
        "details": vmsg
    })


@api_bp.route('/v2/assets/<int:asset_id>/observations', methods=['GET'])
@require_api_key
def api_v2_get_asset_observations(user, asset_id):
    """
    Fetch append-only observation event history for an Asset.
    """
    from models import Observation
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 50)), 200)

    query = Observation.query.filter_by(tenant_id=tenant_id, asset_id=asset.id)
    total = query.count()
    events = query.order_by(Observation.timestamp.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "status": "success",
        "asset_id": asset.id,
        "total": total,
        "page": page,
        "per_page": per_page,
        "observations": [e.to_dict() for e in events]
    })


@api_bp.route('/v2/assets/<int:asset_id>/behavior', methods=['GET'])
@require_api_key
def api_v2_get_asset_behavior(user, asset_id):
    """
    Fetch baseline behavior and active drift events for an Asset.
    """
    from models import BehavioralBaseline, BehavioralDriftEvent
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    baseline = BehavioralBaseline.query.filter_by(tenant_id=tenant_id, asset_id=asset.id).first()
    drifts = BehavioralDriftEvent.query.filter_by(tenant_id=tenant_id, asset_id=asset.id).order_by(BehavioralDriftEvent.created_at.desc()).all()

    return jsonify({
        "status": "success",
        "asset_id": asset.id,
        "baseline": baseline.to_dict() if baseline else None,
        "drifts": [d.to_dict() for d in drifts]
    })


@api_bp.route('/v2/assets/<int:asset_id>/traffic', methods=['GET'])
@require_api_key
def api_v2_get_asset_traffic(user, asset_id):
    """
    Fetch recent traffic flow observations for an Asset.
    """
    from models import Observation
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    flows = Observation.query.filter(
        Observation.tenant_id == tenant_id,
        Observation.asset_id == asset.id,
        Observation.observation_type.in_(['network', 'dns'])
    ).order_by(Observation.timestamp.desc()).limit(100).all()

    return jsonify({
        "status": "success",
        "asset_id": asset.id,
        "total_flows": len(flows),
        "flows": [f.to_dict() for f in flows]
    })


@api_bp.route('/v2/assets/<int:asset_id>/alerts', methods=['GET'])
@require_api_key
def api_v2_get_asset_alerts(user, asset_id):
    """
    Fetch active security alerts for a specific Asset.
    """
    from models import Alert
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    alerts = Alert.query.filter_by(tenant_id=tenant_id, asset_id=asset.id).order_by(Alert.created_at.desc()).all()
    return jsonify({
        "status": "success",
        "asset_id": asset.id,
        "total": len(alerts),
        "alerts": [a.to_dict() for a in alerts]
    })


@api_bp.route('/v2/assets/<int:asset_id>/timeline', methods=['GET'])
@require_api_key
def api_v2_get_asset_timeline(user, asset_id):
    """
    Fetch complete chronological immutable security lifecycle timeline for an Asset.
    """
    from models import AuditEvent, Observation
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    audit_events = AuditEvent.query.filter(
        AuditEvent.tenant_id == tenant_id,
        (AuditEvent.target_id == str(asset.id)) | (AuditEvent.target_type == 'asset')
    ).order_by(AuditEvent.timestamp.desc()).limit(50).all()

    timeline_items = []
    for a in audit_events:
        timeline_items.append({
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "actor": a.actor_username,
            "action": a.action,
            "target": f"asset:{asset.id}",
            "details": json.loads(a.details_json or '{}'),
            "result": a.result
        })

    return jsonify({
        "status": "success",
        "asset_id": asset.id,
        "timeline": timeline_items
    })


@api_bp.route('/v2/alerts/<int:alert_id>', methods=['GET'])
@require_api_key
def api_v2_get_alert_detail(user, alert_id):
    """
    Fetch explicit 'Why did this alert fire?' detail and evidence.
    """
    from models import Alert
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    alert = Alert.query.filter_by(id=alert_id, tenant_id=tenant_id).first()
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    return jsonify({
        "status": "success",
        "alert": alert.to_dict()
    })


@api_bp.route('/v2/scheduled-scans', methods=['POST'])
@require_api_key
def api_v2_create_scheduled_scan(user):
    """
    Create a new recurring scheduled scan.
    """
    from scheduler_engine import scheduler_engine
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    data = request.get_json() or {}
    target_scope = data.get("target_scope")
    if not target_scope:
        return jsonify({"error": "target_scope is required"}), 400

    profile = data.get("profile", "safe")
    frequency = data.get("frequency", "daily")
    site_id = data.get("site_id", "default_site")

    schedule = scheduler_engine.create_schedule(
        user_id=user.id,
        tenant_id=tenant_id,
        target_scope=target_scope,
        site_id=site_id,
        profile=profile,
        frequency=frequency
    )

    return jsonify({
        "status": "success",
        "schedule": schedule.to_dict()
    }), 201


@api_bp.route('/v2/scheduled-scans', methods=['GET'])
@require_api_key
def api_v2_list_scheduled_scans(user):
    """
    List active recurring discovery schedules.
    """
    from models import ScheduledScan
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    schedules = ScheduledScan.query.filter_by(tenant_id=tenant_id).all()
    return jsonify({
        "status": "success",
        "schedules": [s.to_dict() for s in schedules]
    })


# ==============================================================================
# Phase 3: Fleet Management, MSSP Triage, Reports, Notifications & Entitlements
# ==============================================================================

@api_bp.route('/v3/collectors/<int:collector_id>/rotate-token', methods=['POST'])
@require_api_key
def api_v3_rotate_collector_token(user, collector_id):
    from collector_manager import collector_manager
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    try:
        collector, raw_token = collector_manager.rotate_token(collector_id, tenant_id)
        return jsonify({
            "status": "success",
            "message": "Collector token rotated successfully. Save it securely.",
            "collector": collector.to_dict(),
            "new_sensor_token": raw_token
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404


@api_bp.route('/v3/collectors/<int:collector_id>/revoke', methods=['POST'])
@require_api_key
def api_v3_revoke_collector(user, collector_id):
    from collector_manager import collector_manager
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    try:
        collector = collector_manager.revoke_collector(collector_id, tenant_id)
        return jsonify({
            "status": "success",
            "message": "Collector credentials permanently revoked.",
            "collector": collector.to_dict()
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404


@api_bp.route('/v3/collectors/<int:collector_id>/reactivate', methods=['POST'])
@require_api_key
def api_v3_reactivate_collector(user, collector_id):
    from collector_manager import collector_manager
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    try:
        collector, raw_token = collector_manager.reactivate_collector(collector_id, tenant_id)
        return jsonify({
            "status": "success",
            "message": "Collector reactivated with fresh credentials.",
            "collector": collector.to_dict(),
            "sensor_token": raw_token
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404


@api_bp.route('/v3/fleet/health', methods=['GET'])
@require_api_key
def api_v3_fleet_health(user):
    from collector_manager import collector_manager
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    health = collector_manager.evaluate_fleet_health(tenant_id)
    return jsonify({
        "status": "success",
        "fleet_health": health
    })


@api_bp.route('/v3/sites/<site_id>/posture', methods=['GET'])
@require_api_key
def api_v3_site_posture(user, site_id):
    from mssp_manager import mssp_manager
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    posture = mssp_manager.get_site_posture(tenant_id, site_id)
    return jsonify({
        "status": "success",
        "site_posture": posture
    })


@api_bp.route('/v3/mssp/dashboard', methods=['GET'])
@require_api_key
def api_v3_mssp_dashboard(user):
    from mssp_manager import mssp_manager
    from entitlements_engine import entitlements_engine
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")

    if not entitlements_engine.is_mssp_allowed(tenant_id):
        return jsonify({"error": "MSSP dashboard requires an active 'MSSP' entitlement plan"}), 403

    # In production, list authorized customer tenant IDs
    customer_tenants = [tenant_id, f"{tenant_id}_branch_east", f"{tenant_id}_branch_west"]
    dashboard = mssp_manager.get_mssp_triage_dashboard(customer_tenants)
    return jsonify({
        "status": "success",
        "mssp_dashboard": dashboard
    })


@api_bp.route('/v3/reports/generate', methods=['POST'])
@require_api_key
def api_v3_generate_report(user):
    from reports_engine import reports_engine
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    data = request.get_json() or {}
    report_type = data.get("report_type", "EXECUTIVE_SECURITY_SUMMARY")
    site_id = data.get("site_id")

    try:
        report = reports_engine.generate_report(report_type, tenant_id, site_id)
        return jsonify({"status": "success", "report": report})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400


@api_bp.route('/v3/notifications/test', methods=['POST'])
@require_api_key
def api_v3_test_notification(user):
    from notification_engine import notification_engine
    data = request.get_json() or {}
    channel_type = data.get("channel_type", "webhook")
    destination_url = data.get("destination_url", "https://hooks.slack.com/services/test")
    title = data.get("title", "PrivIoT Critical Test Alert")
    description = data.get("description", "Test notification dispatch verifying delivery pipeline.")
    severity = data.get("severity", "high")

    res = notification_engine.dispatch_alert(
        channel_type=channel_type,
        destination_url=destination_url,
        title=title,
        description=description,
        severity=severity,
        evidence={"test_vector": "manual_trigger", "origin": "control_plane"}
    )
    return jsonify(res)


@api_bp.route('/v3/retention/purge', methods=['POST'])
@require_api_key
def api_v3_purge_retention(user):
    from entitlements_engine import entitlements_engine
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    purged_count = entitlements_engine.purge_expired_telemetry(tenant_id)
    return jsonify({
        "status": "success",
        "purged_observations": purged_count,
        "message": f"Purged {purged_count} observations outside plan retention window"
    })


@api_bp.route('/v3/entitlements', methods=['GET'])
@require_api_key
def api_v3_get_entitlements(user):
    from entitlements_engine import entitlements_engine, PLAN_LIMITS
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    plan = entitlements_engine.get_tenant_plan(tenant_id)
    limits = PLAN_LIMITS[plan]

    from models import Asset, Collector
    current_assets = Asset.query.filter_by(tenant_id=tenant_id).count()
    current_collectors = Collector.query.filter_by(tenant_id=tenant_id).count()

    return jsonify({
        "status": "success",
        "tenant_id": tenant_id,
        "plan": plan,
        "limits": limits,
        "usage": {
            "assets": current_assets,
            "assets_limit": limits["max_assets"],
            "collectors": current_collectors,
            "collectors_limit": limits["max_collectors"]
        }
    })


# ==============================================================================
# Phase 4: Pilot Mode, Safety Gates, Stripe Billing & Disaster Recovery
# ==============================================================================

@api_bp.route('/v4/pilot/status', methods=['GET'])
@require_api_key
def api_v4_pilot_status(user):
    from pilot_engine import pilot_engine
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    status = pilot_engine.get_pilot_status(tenant_id)
    return jsonify({
        "status": "success",
        "pilot_status": status
    })


@api_bp.route('/v4/pilot/readiness-report', methods=['GET'])
@require_api_key
def api_v4_pilot_readiness_report(user):
    from pilot_engine import pilot_engine
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    report = pilot_engine.generate_pilot_readiness_report(tenant_id)
    return jsonify({
        "status": "success",
        "pilot_readiness_report": report
    })


@api_bp.route('/v4/pilot/validate-containment-safety', methods=['POST'])
@require_api_key
def api_v4_validate_safety(user):
    from pilot_engine import pilot_engine
    data = request.get_json() or {}
    asset_id = data.get("asset_id")
    target_policy = data.get("policy", {})

    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first() if asset_id else None

    res = pilot_engine.validate_containment_safety(asset, target_policy)
    return jsonify({
        "status": "success",
        "safety_evaluation": res
    })


@api_bp.route('/v4/billing/stripe/webhook', methods=['POST'])
def api_v4_stripe_webhook():
    from billing_engine import billing_engine
    payload = request.get_json() or {}
    sig_header = request.headers.get('Stripe-Signature')

    ok, msg = billing_engine.process_webhook_event(payload, signature=sig_header)
    if ok:
        return jsonify({"status": "success", "message": msg}), 200
    else:
        return jsonify({"error": msg}), 400


@api_bp.route('/v4/billing/status', methods=['GET'])
@require_api_key
def api_v4_billing_status(user):
    from billing_engine import billing_engine
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    billing = billing_engine.get_billing_status(tenant_id)
    return jsonify({
        "status": "success",
        "billing": billing
    })


@api_bp.route('/v4/backup/export', methods=['POST'])
@require_api_key
def api_v4_export_backup(user):
    from backup_restore import backup_engine
    tenant_id = request.headers.get("X-Tenant-ID", "default_tenant")
    snapshot = backup_engine.export_snapshot(tenant_id=tenant_id)
    return jsonify({
        "status": "success",
        "snapshot": snapshot
    })


@api_bp.route('/v4/backup/verify', methods=['POST'])
@require_api_key
def api_v4_verify_backup(user):
    from backup_restore import backup_engine
    snapshot = request.get_json() or {}
    valid, msg = backup_engine.verify_snapshot_integrity(snapshot)
    if valid:
        return jsonify({"status": "success", "verified": True, "details": msg})
    else:
        return jsonify({"status": "error", "verified": False, "error": msg}), 400








