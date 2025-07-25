import os
import json
import uuid
from datetime import datetime, timedelta
from flask import render_template, redirect, url_for, flash, request, jsonify, abort, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db, csrf
from models import User, Device, Scan, Vulnerability, PrivacyIssue, Report, UserActivity, DeviceGroup
from security_scanner import scan_device
from report_generator import generate_report
from sqlalchemy import func, desc


def log_user_activity(activity_type, activity_data=None):
    """Log user activity for analytics and security"""
    if current_user.is_authenticated:
        try:
            activity = UserActivity(
                user_id=current_user.id,
                activity_type=activity_type,
                activity_data=json.dumps(activity_data) if activity_data else None,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')[:255]
            )
            db.session.add(activity)
            db.session.commit()
        except Exception as e:
            app.logger.error(f"Failed to log user activity: {str(e)}")
            db.session.rollback()


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            # Update last login time
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            login_user(user, remember=True)
            log_user_activity('login')
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            log_user_activity('failed_login', {'username': username})
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        
        user_exists = User.query.filter_by(username=username).first()
        email_exists = User.query.filter_by(email=email).first()
        
        if user_exists:
            flash('Username already exists. Please choose a different one.', 'danger')
        elif email_exists:
            flash('Email already registered. Please use a different email.', 'danger')
        else:
            api_key = str(uuid.uuid4())
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                api_key=api_key
            )
            db.session.add(new_user)
            db.session.commit()
            log_user_activity('registration', {'username': username})
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    log_user_activity('logout')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    log_user_activity('dashboard_view')
    
    # Get user's devices
    devices = Device.query.filter_by(user_id=current_user.id).all()
    
    # Get recent scans
    recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.scan_date.desc()).limit(5).all()
    
    # Calculate device statistics
    total_devices = len(devices)
    vulnerable_devices = sum(1 for device in devices if 
                           device.scans.filter(Scan.status == 'completed').first() and 
                           device.scans.filter(Scan.status == 'completed').first().security_score < 7.0)
    
    # Calculate average security and privacy scores
    completed_scans = Scan.query.filter_by(user_id=current_user.id, status='completed').all()
    avg_security_score = sum(scan.security_score for scan in completed_scans if scan.security_score) / len(completed_scans) if completed_scans else 0
    avg_privacy_score = sum(scan.privacy_score for scan in completed_scans if scan.privacy_score) / len(completed_scans) if completed_scans else 0
    
    # Get critical vulnerabilities
    critical_vulnerabilities = Vulnerability.query.join(Scan).filter(
        Scan.user_id == current_user.id,
        Vulnerability.severity == 'critical',
        Vulnerability.status == 'open'
    ).limit(5).all()
    
    # Get security trends (last 30 days)
    security_trend = db.session.query(
        func.date(Scan.scan_date).label('date'),
        func.avg(Scan.security_score).label('avg_score')
    ).filter(
        Scan.user_id == current_user.id,
        Scan.status == 'completed',
        Scan.scan_date >= datetime.utcnow() - timedelta(days=30)
    ).group_by(func.date(Scan.scan_date)).all()
    
    # Get device groups
    device_groups = DeviceGroup.query.filter_by(user_id=current_user.id).all()
    
    # Get recommendations based on current vulnerabilities
    recommendations = _generate_dashboard_recommendations(devices, critical_vulnerabilities)
    
    return render_template('dashboard.html', 
                          devices=devices,
                          recent_scans=recent_scans,
                          total_devices=total_devices,
                          vulnerable_devices=vulnerable_devices,
                          avg_security_score=avg_security_score,
                          avg_privacy_score=avg_privacy_score,
                          critical_vulnerabilities=critical_vulnerabilities,
                          security_trend=security_trend,
                          device_groups=device_groups,
                          recommendations=recommendations)


@app.route('/devices', methods=['GET', 'POST'])
@login_required
def devices():
    if request.method == 'POST':
        log_user_activity('device_add')
        
        name = request.form.get('name')
        device_type = request.form.get('device_type')
        manufacturer = request.form.get('manufacturer')
        model = request.form.get('model')
        firmware_version = request.form.get('firmware_version')
        ip_address = request.form.get('ip_address')
        mac_address = request.form.get('mac_address')
        location = request.form.get('location')
        description = request.form.get('description')
        group_id = request.form.get('group_id')
        
        if not name or not device_type:
            flash('Device name and type are required.', 'danger')
        else:
            try:
                new_device = Device(
                    name=name,
                    device_type=device_type,
                    manufacturer=manufacturer,
                    model=model,
                    firmware_version=firmware_version,
                    ip_address=ip_address,
                    mac_address=mac_address,
                    location=location,
                    description=description,
                    user_id=current_user.id
                )
                db.session.add(new_device)
                db.session.flush()  # Get the device ID
                
                # Add to group if specified
                if group_id:
                    group = DeviceGroup.query.filter_by(id=group_id, user_id=current_user.id).first()
                    if group:
                        new_device.groups.append(group)
                
                db.session.commit()
                flash('Device added successfully!', 'success')
                return redirect(url_for('devices'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error adding device: {str(e)}")
                flash('Error adding device. Please try again.', 'danger')
    
    user_devices = Device.query.filter_by(user_id=current_user.id).all()
    device_groups = DeviceGroup.query.filter_by(user_id=current_user.id).all()
    
    return render_template('devices.html', devices=user_devices, device_groups=device_groups)


@app.route('/device/<int:device_id>')
@login_required
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)
    
    # Check if the device belongs to the current user
    if device.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to view this device.', 'danger')
        return redirect(url_for('devices'))
    
    # Get the most recent scan
    latest_scan = Scan.query.filter_by(device_id=device.id).order_by(Scan.scan_date.desc()).first()
    
    return render_template('device_detail.html', device=device, latest_scan=latest_scan)


@app.route('/device/<int:device_id>/scan', methods=['POST'])
@login_required
def start_scan(device_id):
    log_user_activity('scan_start', {'device_id': device_id})
    
    device = Device.query.get_or_404(device_id)
    
    # Check if the device belongs to the current user
    if device.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to scan this device.', 'danger')
        return redirect(url_for('devices'))
    
    # Check if there's already a scan in progress
    in_progress = Scan.query.filter_by(device_id=device.id, status='running').first()
    if in_progress:
        flash('A scan is already in progress for this device.', 'warning')
        return redirect(url_for('device_detail', device_id=device.id))
    
    # Create a new scan
    new_scan = Scan(
        device_id=device.id,
        user_id=current_user.id,
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
        new_scan.scan_duration = scan_result.get('scan_duration', 0)
        new_scan.anomalies_detected = len(scan_result.get('anomalies', []))
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
                auto_remediable=vuln.get('auto_remediable', False),
                remediation_complexity=vuln.get('remediation_complexity', 'medium'),
                estimated_fix_time=vuln.get('estimated_fix_time', '30-60 minutes'),
                scan_id=new_scan.id
            )
            if vuln.get('remediation_steps'):
                vulnerability.set_remediation_steps(vuln['remediation_steps'])
            db.session.add(vulnerability)
        
        # Add privacy issues from scan
        for issue in scan_result.get('privacy_issues', []):
            privacy_issue = PrivacyIssue(
                name=issue.get('name', ''),
                description=issue.get('description', ''),
                severity=issue.get('severity', 'medium'),
                privacy_impact=issue.get('privacy_impact', 0),
                recommendation=issue.get('recommendation', ''),
                compliance_impact=json.dumps(issue.get('compliance_impact', [])),
                scan_id=new_scan.id
            )
            if issue.get('data_types_affected'):
                privacy_issue.set_data_types_affected(issue['data_types_affected'])
            db.session.add(privacy_issue)
        
        # Update device last scan date
        device.last_scan_date = new_scan.scan_date
        
        db.session.commit()
        log_user_activity('scan_complete', {'device_id': device_id, 'scan_id': new_scan.id})
        flash('Scan completed successfully!', 'success')
        
    except Exception as e:
        new_scan.status = 'failed'
        db.session.commit()
        log_user_activity('scan_failed', {'device_id': device_id, 'error': str(e)})
        flash(f'Scan failed: {str(e)}', 'danger')
    
    return redirect(url_for('scan_detail', scan_id=new_scan.id))


@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Check if the scan belongs to the current user
    if scan.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to view this scan.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get vulnerabilities and privacy issues
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).all()
    privacy_issues = PrivacyIssue.query.filter_by(scan_id=scan.id).all()
    
    return render_template('scan_detail.html', 
                          scan=scan,
                          device=scan.device,
                          vulnerabilities=vulnerabilities,
                          privacy_issues=privacy_issues)


@app.route('/scan/<int:scan_id>/generate_report', methods=['POST'])
@login_required
def generate_scan_report(scan_id):
    log_user_activity('report_generate', {'scan_id': scan_id})
    
    scan = Scan.query.get_or_404(scan_id)
    
    # Check if the scan belongs to the current user
    if scan.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to generate a report for this scan.', 'danger')
        return redirect(url_for('dashboard'))
    
    report_type = request.form.get('report_type', 'detailed')
    
    # Generate report content
    report_content = generate_report(scan, report_type)
    
    # Create a new report
    title = f"{scan.device.name} Security Report - {datetime.utcnow().strftime('%Y-%m-%d')}"
    new_report = Report(
        title=title,
        report_type=report_type,
        content=report_content,
        scan_id=scan.id,
        user_id=current_user.id
    )
    db.session.add(new_report)
    db.session.commit()
    
    flash('Report generated successfully!', 'success')
    return redirect(url_for('report_detail', report_id=new_report.id))


@app.route('/reports')
@login_required
def reports():
    user_reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.generated_at.desc()).all()
    return render_template('reports.html', reports=user_reports)


@app.route('/report/<int:report_id>')
@login_required
def report_detail(report_id):
    report = Report.query.get_or_404(report_id)
    
    # Check if the report belongs to the current user
    if report.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to view this report.', 'danger')
        return redirect(url_for('reports'))
    
    return render_template('report_detail.html', report=report)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Update profile information
        current_user.username = request.form.get('username', current_user.username)
        current_user.email = request.form.get('email', current_user.email)
        
        # Check if password is being updated
        new_password = request.form.get('new_password')
        if new_password:
            current_password = request.form.get('current_password')
            if not check_password_hash(current_user.password_hash, current_password):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('profile'))
            
            confirm_password = request.form.get('confirm_password')
            if new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
                return redirect(url_for('profile'))
            
            current_user.password_hash = generate_password_hash(new_password)
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    # Generate a new API key if requested
    if request.args.get('regenerate_api_key') == 'true':
        current_user.api_key = str(uuid.uuid4())
        db.session.commit()
        flash('API key regenerated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=current_user)


@app.route('/device_groups', methods=['GET', 'POST'])
@login_required
def device_groups():
    """Manage device groups"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        color = request.form.get('color', '#6366F1')
        
        if not name:
            flash('Group name is required.', 'danger')
        else:
            try:
                new_group = DeviceGroup(
                    name=name,
                    description=description,
                    color=color,
                    user_id=current_user.id
                )
                db.session.add(new_group)
                db.session.commit()
                flash('Device group created successfully!', 'success')
                return redirect(url_for('device_groups'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error creating device group: {str(e)}")
                flash('Error creating device group. Please try again.', 'danger')
    
    groups = DeviceGroup.query.filter_by(user_id=current_user.id).all()
    return render_template('device_groups.html', groups=groups)


@app.route('/recommendations')
@login_required
def recommendations():
    """Show personalized security recommendations"""
    log_user_activity('recommendations_view')
    
    # Get user's devices and recent scans
    devices = Device.query.filter_by(user_id=current_user.id).all()
    recent_scans = Scan.query.filter_by(user_id=current_user.id, status='completed').order_by(Scan.scan_date.desc()).limit(10).all()
    
    # Get open vulnerabilities
    open_vulnerabilities = Vulnerability.query.join(Scan).filter(
        Scan.user_id == current_user.id,
        Vulnerability.status == 'open'
    ).order_by(desc(Vulnerability.cvss_score)).all()
    
    # Generate personalized recommendations
    recommendations = _generate_personalized_recommendations(devices, recent_scans, open_vulnerabilities)
    
    return render_template('recommendations.html', 
                          recommendations=recommendations,
                          devices=devices,
                          open_vulnerabilities=open_vulnerabilities)


@app.route('/api/vulnerability/<int:vuln_id>/status', methods=['POST'])
@login_required
@csrf.exempt
def update_vulnerability_status(vuln_id):
    """Update vulnerability status"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['open', 'resolved', 'false_positive']:
            return jsonify({'error': 'Invalid status'}), 400
        
        vulnerability = Vulnerability.query.join(Scan).filter(
            Vulnerability.id == vuln_id,
            Scan.user_id == current_user.id
        ).first()
        
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        vulnerability.status = new_status
        if new_status == 'resolved':
            vulnerability.resolved_at = datetime.utcnow()
        
        db.session.commit()
        log_user_activity('vulnerability_status_update', {'vulnerability_id': vuln_id, 'status': new_status})
        
        return jsonify({'success': True, 'message': 'Status updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating vulnerability status: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api_docs')
@login_required
def api_docs():
    return render_template('api_docs.html', api_key=current_user.api_key)


@app.context_processor
def inject_theme():
    # Default to dark mode
    if 'theme' not in session:
        session['theme'] = 'dark'
    return dict(theme=session['theme'])


@app.context_processor
def inject_models():
    """Make models available to all templates"""
    from models import Scan
    return dict(Scan=Scan)


@app.context_processor
def inject_alerts_count():
    """Add alerts count to all templates"""
    alerts_count = 0
    if current_user.is_authenticated:
        # In a real implementation, this would query the database for unread alerts
        # For now, we'll just use a sample count
        alerts_count = 3
    return dict(alerts_count=alerts_count)


@app.route('/toggle_theme')
def toggle_theme():
    session['theme'] = 'light' if session.get('theme') == 'dark' else 'dark'
    return redirect(request.referrer or url_for('index'))


def _generate_dashboard_recommendations(devices, critical_vulnerabilities):
    """Generate dashboard recommendations based on user's current state"""
    recommendations = []
    
    # No devices recommendation
    if not devices:
        recommendations.append({
            'type': 'setup',
            'title': 'Add Your First Device',
            'description': 'Start securing your IoT ecosystem by adding your first device.',
            'action': 'Add Device',
            'url': url_for('devices'),
            'priority': 'high'
        })
        return recommendations
    
    # Unscanned devices
    unscanned_devices = [d for d in devices if not d.get_latest_scan()]
    if unscanned_devices:
        recommendations.append({
            'type': 'scan',
            'title': f'Scan {len(unscanned_devices)} Unscanned Device(s)',
            'description': 'These devices haven\'t been scanned for security vulnerabilities yet.',
            'action': 'Start Scanning',
            'url': url_for('devices'),
            'priority': 'medium'
        })
    
    # Critical vulnerabilities
    if critical_vulnerabilities:
        recommendations.append({
            'type': 'security',
            'title': f'Fix {len(critical_vulnerabilities)} Critical Vulnerabilities',
            'description': 'These vulnerabilities pose immediate security risks and should be addressed urgently.',
            'action': 'View Vulnerabilities',
            'url': url_for('remediation'),
            'priority': 'critical'
        })
    
    # Outdated scans
    outdated_devices = [d for d in devices if d.get_latest_scan() and 
                       (datetime.utcnow() - d.get_latest_scan().scan_date).days > 30]
    if outdated_devices:
        recommendations.append({
            'type': 'maintenance',
            'title': f'Update {len(outdated_devices)} Outdated Scan(s)',
            'description': 'These devices haven\'t been scanned in over 30 days.',
            'action': 'Rescan Devices',
            'url': url_for('devices'),
            'priority': 'low'
        })
    
    return recommendations


def _generate_personalized_recommendations(devices, recent_scans, open_vulnerabilities):
    """Generate personalized security recommendations"""
    recommendations = {
        'immediate_actions': [],
        'security_improvements': [],
        'best_practices': [],
        'device_specific': {}
    }
    
    # Immediate actions for critical vulnerabilities
    critical_vulns = [v for v in open_vulnerabilities if v.severity == 'critical']
    for vuln in critical_vulns[:3]:  # Top 3 critical
        recommendations['immediate_actions'].append({
            'title': f'Fix Critical: {vuln.name}',
            'description': vuln.description,
            'device': vuln.scan.device.name,
            'steps': vuln.get_remediation_steps(),
            'estimated_time': vuln.estimated_fix_time,
            'difficulty': vuln.remediation_complexity,
            'priority': 1
        })
    
    # Security improvements
    if any(scan.security_score < 7.0 for scan in recent_scans):
        recommendations['security_improvements'].append({
            'title': 'Improve Overall Security Score',
            'description': 'Your average security score could be improved by addressing medium and high severity vulnerabilities.',
            'action': 'Review all vulnerabilities and prioritize fixes based on CVSS scores.'
        })
    
    # Best practices
    recommendations['best_practices'] = [
        {
            'title': 'Regular Security Scans',
            'description': 'Scan your devices monthly to catch new vulnerabilities.',
            'implementation': 'Set up a monthly reminder to run security scans on all devices.'
        },
        {
            'title': 'Keep Firmware Updated',
            'description': 'Regularly check for and install firmware updates.',
            'implementation': 'Enable automatic updates where available, or check monthly for updates.'
        },
        {
            'title': 'Network Segmentation',
            'description': 'Isolate IoT devices on a separate network.',
            'implementation': 'Configure a guest network or IoT VLAN for your smart devices.'
        }
    ]
    
    # Device-specific recommendations
    for device in devices:
        latest_scan = device.get_latest_scan()
        if latest_scan and latest_scan.status == 'completed':
            device_vulns = latest_scan.vulnerabilities.filter_by(status='open').all()
            if device_vulns:
                recommendations['device_specific'][device.name] = {
                    'vulnerability_count': len(device_vulns),
                    'top_priority': device_vulns[0] if device_vulns else None,
                    'security_score': latest_scan.security_score,
                    'recommended_action': _get_device_recommendation(device, latest_scan)
                }
    
    return recommendations


def _get_device_recommendation(device, scan):
    """Get specific recommendation for a device based on its scan results"""
    if scan.security_score < 4.0:
        return f"Immediate attention required for {device.name}. Multiple critical vulnerabilities detected."
    elif scan.security_score < 6.0:
        return f"Address high-priority vulnerabilities on {device.name} to improve security."
    elif scan.security_score < 8.0:
        return f"{device.name} has good security but could be improved with minor fixes."
    else:
        return f"{device.name} has excellent security. Continue monitoring for new threats."


@app.route('/alerts')
@login_required
def alerts():
    # In a production environment, we would query the database for real alerts
    # For this demo, we'll create sample alerts
    sample_alerts = [
        {
            'id': 1,
            'title': 'Critical Vulnerability Detected',
            'message': 'A critical vulnerability was detected on your smart camera. This vulnerability could allow an attacker to gain unauthorized access to the device and view camera footage.',
            'severity': 'critical',
            'type': 'vulnerability',
            'timestamp': '2025-04-06 14:22:31',
            'device': {'id': 1, 'name': 'Living Room Camera', 'device_type': 'IP Camera'},
            'scan_id': 1,
            'recommendation': 'Update the firmware immediately to version 3.2.1 or later.'
        },
        {
            'id': 2,
            'title': 'Unusual Network Traffic Detected',
            'message': 'Your smart speaker is showing abnormal network traffic patterns. The device is transmitting significantly more data than usual, which could indicate unauthorized access or malware.',
            'severity': 'high',
            'type': 'anomaly',
            'timestamp': '2025-04-07 08:15:47',
            'device': {'id': 2, 'name': 'Kitchen Speaker', 'device_type': 'Smart Speaker'},
            'recommendation': 'Check device for unauthorized access and consider resetting to factory defaults.'
        },
        {
            'id': 3,
            'title': 'Authentication Failures',
            'message': 'Multiple failed authentication attempts were detected on your smart thermostat. This could indicate a brute force attack attempt.',
            'severity': 'medium',
            'type': 'anomaly',
            'timestamp': '2025-04-07 10:33:12',
            'device': {'id': 3, 'name': 'Hallway Thermostat', 'device_type': 'Smart Thermostat'},
            'recommendation': 'Change the device password immediately and enable two-factor authentication if available.'
        }
    ]
    
    # Get all user devices for the filter dropdown
    devices = Device.query.filter_by(user_id=current_user.id).all()
    
    # Alert stats for the dashboard
    stats = {
        'critical': 1,
        'high': 1,
        'medium': 1,
        'low': 0
    }
    
    return render_template('alerts.html', alerts=sample_alerts, devices=devices, stats=stats)


# Helper function to get sample vulnerabilities
def get_sample_vulnerabilities():
    return [
        {
            'id': 1,
            'name': 'Default Admin Credentials',
            'description': 'The device is using factory default administrator credentials, which are publicly known and can be easily exploited.',
            'severity': 'critical',
            'cvss_score': 9.8,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'status': 'open',
            'device': {'id': 1, 'name': 'Living Room Camera', 'device_type': 'IP Camera'},
            'detected_at': '2025-04-06 14:22:31',
            'auto_remediable': True,
            'type': 'default_credentials',
            'manual_steps': [
                'Log in to the device administration panel using the current credentials.',
                'Navigate to the user/password settings section.',
                'Change the default password to a strong, unique password.',
                'Consider enabling two-factor authentication if available.'
            ]
        },
        {
            'id': 2,
            'name': 'Outdated Firmware (v1.2.3)',
            'description': 'The device is running outdated firmware with known security vulnerabilities. The latest firmware (v2.0.1) includes patches for critical security issues.',
            'severity': 'high',
            'cvss_score': 8.2,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'status': 'in_progress',
            'device': {'id': 2, 'name': 'Kitchen Speaker', 'device_type': 'Smart Speaker'},
            'detected_at': '2025-04-07 09:15:42',
            'auto_remediable': True,
            'type': 'outdated_firmware',
            'auto_remediation_status': {
                'success': False,
                'message': 'Unable to establish a secure connection to the device. Please follow the manual remediation steps.',
                'method': 'firmware_update'
            },
            'manual_steps': [
                'Download the latest firmware (v2.0.1) from the manufacturer website.',
                'Follow the manufacturer instructions to install the firmware update.',
                'After updating, restart the device and verify the new firmware version.'
            ],
            'timeline': [
                {
                    'timestamp': '2025-04-07 09:15:42',
                    'title': 'Vulnerability Detected',
                    'description': 'Security scan identified outdated firmware v1.2.3',
                    'icon': 'danger',
                    'icon_class': 'exclamation-triangle'
                },
                {
                    'timestamp': '2025-04-07 10:30:15',
                    'title': 'Auto-Remediation Attempted',
                    'description': 'Automatic firmware update failed due to connection issues',
                    'icon': 'warning',
                    'icon_class': 'times'
                },
                {
                    'timestamp': '2025-04-07 11:45:22',
                    'title': 'Manual Remediation Started',
                    'description': 'User began manual firmware update process',
                    'icon': 'info',
                    'icon_class': 'tools'
                }
            ]
        },
        {
            'id': 3,
            'name': 'Insecure HTTP Access',
            'description': 'The device web interface is accessible over unencrypted HTTP, which could allow attackers to intercept sensitive information including credentials.',
            'severity': 'medium',
            'cvss_score': 6.5,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'status': 'open',
            'device': {'id': 3, 'name': 'Hallway Thermostat', 'device_type': 'Smart Thermostat'},
            'detected_at': '2025-04-07 08:33:19',
            'auto_remediable': False,
            'type': 'insecure_http',
            'manual_steps': [
                'Log in to the device administration panel.',
                'Navigate to the network or security settings.',
                'Disable HTTP access and enable HTTPS.',
                'Ensure a valid SSL certificate is installed.',
                'Verify that you can only access the interface via HTTPS.'
            ]
        },
        {
            'id': 4,
            'name': 'Unnecessary Open Ports',
            'description': 'The device has multiple unnecessary ports open (23/Telnet, 21/FTP, 161/SNMP) that increase the attack surface.',
            'severity': 'high',
            'cvss_score': 7.8,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'status': 'resolved',
            'device': {'id': 1, 'name': 'Living Room Camera', 'device_type': 'IP Camera'},
            'detected_at': '2025-04-05 15:11:27',
            'resolved_at': '2025-04-06 09:45:33',
            'resolution_method': 'Manual remediation: User disabled unnecessary services via the device administration panel',
            'auto_remediable': True,
            'type': 'open_ports',
            'manual_steps': [
                'Log in to the device administration panel.',
                'Navigate to the network or service settings.',
                'Disable unnecessary services (Telnet, FTP, SNMP).',
                'Save settings and restart the device if required.',
                'Verify ports are closed using a port scanner.'
            ],
            'timeline': [
                {
                    'timestamp': '2025-04-05 15:11:27',
                    'title': 'Vulnerability Detected',
                    'description': 'Security scan identified multiple unnecessary open ports',
                    'icon': 'danger',
                    'icon_class': 'exclamation-triangle'
                },
                {
                    'timestamp': '2025-04-06 09:22:45',
                    'title': 'Manual Remediation Started',
                    'description': 'User accessed device administration panel',
                    'icon': 'info',
                    'icon_class': 'tools'
                },
                {
                    'timestamp': '2025-04-06 09:45:33',
                    'title': 'Vulnerability Resolved',
                    'description': 'Unnecessary services disabled and port scan confirmed closure',
                    'icon': 'success',
                    'icon_class': 'check'
                }
            ]
        },
        {
            'id': 5,
            'name': 'WPA2 with Weak Passphrase',
            'description': 'The device is using WPA2 with a weak passphrase that could be vulnerable to brute force attacks.',
            'severity': 'medium',
            'cvss_score': 5.9,
            'cvss_vector': 'CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
            'status': 'false_positive',
            'device': {'id': 2, 'name': 'Kitchen Speaker', 'device_type': 'Smart Speaker'},
            'detected_at': '2025-04-07 11:22:13',
            'auto_remediable': False,
            'type': 'wifi_security',
            'manual_steps': [
                'Log in to the device administration panel.',
                'Navigate to the Wi-Fi or network settings.',
                'Update the Wi-Fi passphrase to a strong, complex one (>14 characters with mixed case, numbers, symbols).',
                'Save settings and reconnect devices to the network with the new passphrase.'
            ]
        }
    ]


@app.route('/remediation')
@login_required
def remediation():
    # Get all user devices
    devices = Device.query.filter_by(user_id=current_user.id).all()
    
    # Get sample vulnerabilities for the demo
    sample_vulnerabilities = get_sample_vulnerabilities()
    
    # Stats for the dashboard
    stats = {
        'auto_remediable': 3,
        'in_progress': 1,
        'resolved': 1
    }
    
    return render_template('remediation.html', vulnerabilities=sample_vulnerabilities, devices=devices, stats=stats)


@app.route('/api/remediate/<int:vulnerability_id>', methods=['POST'])
@login_required
@csrf.exempt
def remediate_vulnerability(vulnerability_id):
    """API endpoint to trigger automatic remediation for a vulnerability"""
    # In a production implementation, this would:
    # 1. Look up the vulnerability and device
    # 2. Use the vulnerability_remediation module to attempt remediation
    # 3. Update the database with results
    # 4. Return the results
    
    try:
        # Import the remediation functionality
        from vulnerability_remediation import remediate_vulnerability
        
        # In production, fetch vulnerability and device from database
        # For demo, find the vulnerability in our sample data - get function-local copy
        sample_vulnerabilities = get_sample_vulnerabilities()
        
        vulnerability = None
        for vuln in sample_vulnerabilities:
            if vuln['id'] == vulnerability_id:
                vulnerability = vuln
                break
                
        if not vulnerability:
            return jsonify({
                'success': False,
                'message': f"Vulnerability with ID {vulnerability_id} not found",
                'vulnerability_id': vulnerability_id
            }), 404
        
        # Get device information
        device = vulnerability.get('device', {})
        
        # Add vulnerability type based on name if not present
        if 'type' not in vulnerability:
            vulnerability['type'] = vulnerability['name'].lower().replace(' ', '_')
            
        # Run remediation
        result = remediate_vulnerability(vulnerability, device)
        
        # In production, update vulnerability status in database
        # For demo, just return the result
        return jsonify(result), 200
        
    except Exception as e:
        app.logger.error(f"Error in vulnerability remediation: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/batch-remediate', methods=['POST'])
@login_required
@csrf.exempt
def batch_remediate_vulnerabilities():
    """API endpoint to trigger batch remediation for multiple vulnerabilities"""
    try:
        # Get vulnerability IDs from request
        data = request.get_json()
        vulnerability_ids = data.get('vulnerability_ids', [])
        
        if not vulnerability_ids:
            return jsonify({
                'success': False,
                'message': "No vulnerability IDs provided",
                'total': 0,
                'successful': 0,
                'failed': 0,
                'skipped': 0,
                'details': []
            }), 400
            
        # Import the batch remediation functionality
        from vulnerability_remediation import batch_remediate_vulnerabilities
        
        # Collect vulnerabilities to remediate
        vulnerabilities_to_remediate = []
        devices = {}
        
        # In production, fetch vulnerabilities from database
        # For demo, find vulnerabilities in our sample data
        sample_vulnerabilities = get_sample_vulnerabilities()
        
        for vuln_id in vulnerability_ids:
            for vuln in sample_vulnerabilities:
                if vuln['id'] == int(vuln_id):
                    # Add type if not present
                    if 'type' not in vuln:
                        vuln['type'] = vuln['name'].lower().replace(' ', '_')
                        
                    vulnerabilities_to_remediate.append(vuln)
                    
                    # Add device to devices dict
                    if 'device' in vuln:
                        device = vuln['device']
                        devices[device.get('id')] = device
                    
                    break
        
        # Run batch remediation
        result = batch_remediate_vulnerabilities(vulnerabilities_to_remediate, devices)
        
        # In production, update vulnerability statuses in database
        # For demo, just return the result
        return jsonify(result), 200
        
    except Exception as e:
        app.logger.error(f"Error in batch vulnerability remediation: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500