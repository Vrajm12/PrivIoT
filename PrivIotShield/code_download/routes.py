import os
import json
import uuid
from datetime import datetime
from flask import render_template, redirect, url_for, flash, request, jsonify, abort, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from models import User, Device, Scan, Vulnerability, PrivacyIssue, Report
from security_scanner import scan_device
from report_generator import generate_report


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
            login_user(user, remember=True)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
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
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
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
    
    return render_template('dashboard.html', 
                          devices=devices,
                          recent_scans=recent_scans,
                          total_devices=total_devices,
                          vulnerable_devices=vulnerable_devices,
                          avg_security_score=avg_security_score,
                          avg_privacy_score=avg_privacy_score,
                          critical_vulnerabilities=critical_vulnerabilities)


@app.route('/devices', methods=['GET', 'POST'])
@login_required
def devices():
    if request.method == 'POST':
        name = request.form.get('name')
        device_type = request.form.get('device_type')
        manufacturer = request.form.get('manufacturer')
        model = request.form.get('model')
        firmware_version = request.form.get('firmware_version')
        ip_address = request.form.get('ip_address')
        mac_address = request.form.get('mac_address')
        location = request.form.get('location')
        description = request.form.get('description')
        
        if not name or not device_type:
            flash('Device name and type are required.', 'danger')
        else:
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
            db.session.commit()
            flash('Device added successfully!', 'success')
            return redirect(url_for('devices'))
    
    user_devices = Device.query.filter_by(user_id=current_user.id).all()
    return render_template('devices.html', devices=user_devices)


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
        flash('Scan completed successfully!', 'success')
        
    except Exception as e:
        new_scan.status = 'failed'
        db.session.commit()
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


@app.route('/toggle_theme')
def toggle_theme():
    session['theme'] = 'light' if session.get('theme') == 'dark' else 'dark'
    return redirect(request.referrer or url_for('index'))
