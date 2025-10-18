"""
Export Service for generating reports in multiple formats (PDF, CSV, JSON, Excel)
"""
import os
import io
import csv
import json
import logging
from datetime import datetime
from flask import make_response
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
import matplotlib
matplotlib.use('Agg')  # Non-GUI backend
import matplotlib.pyplot as plt
from io import BytesIO
import base64

logger = logging.getLogger(__name__)


class ReportExporter:
    """Handle export of reports in various formats"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for PDF"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1e3a8a'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#3b82f6'),
            spaceAfter=12,
            spaceBefore=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskCritical',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontSize=12,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            fontSize=12,
            fontName='Helvetica-Bold'
        ))
    
    def export_to_pdf(self, scan, report_data, report_type='detailed'):
        """
        Generate PDF report
        
        Args:
            scan: Scan object
            report_data: Dictionary containing report data
            report_type: Type of report (detailed, summary, executive)
        
        Returns:
            BytesIO: PDF file buffer
        """
        try:
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter,
                                   rightMargin=72, leftMargin=72,
                                   topMargin=72, bottomMargin=18)
            
            # Container for the 'Flowable' objects
            elements = []
            
            # Title
            title = Paragraph(f"PrivIoT Security Report - {report_type.title()}", 
                            self.styles['CustomTitle'])
            elements.append(title)
            elements.append(Spacer(1, 12))
            
            # Report metadata
            metadata = [
                ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Scan ID:', str(scan.id)],
                ['Scan Date:', scan.scan_date.strftime('%Y-%m-%d %H:%M:%S')],
                ['Device Name:', scan.device.name],
                ['Device Type:', scan.device.device_type or 'Unknown']
            ]
            
            metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
            metadata_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e5e7eb')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            elements.append(metadata_table)
            elements.append(Spacer(1, 20))
            
            # Security Score Summary
            elements.append(Paragraph("Security Score Summary", self.styles['SectionHeader']))
            
            scores = [
                ['Metric', 'Score', 'Risk Level'],
                ['Overall Security Score', f"{scan.overall_score:.1f}/10", scan.risk_level.upper()],
                ['Security Score', f"{scan.security_score:.1f}/10", self._get_risk_level(scan.security_score)],
                ['Privacy Score', f"{scan.privacy_score:.1f}/10", self._get_risk_level(scan.privacy_score)]
            ]
            
            score_table = Table(scores, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
            score_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
            ]))
            elements.append(score_table)
            elements.append(Spacer(1, 20))
            
            # Vulnerabilities Section
            if scan.vulnerabilities.count() > 0:
                elements.append(Paragraph("Vulnerabilities Detected", self.styles['SectionHeader']))
                
                vuln_data = [['ID', 'Name', 'Severity', 'CVSS Score']]
                for vuln in scan.vulnerabilities.all():
                    vuln_data.append([
                        str(vuln.id),
                        vuln.name[:40] + '...' if len(vuln.name) > 40 else vuln.name,
                        vuln.severity.upper(),
                        f"{vuln.cvss_score:.1f}"
                    ])
                
                vuln_table = Table(vuln_data, colWidths=[0.5*inch, 3*inch, 1.2*inch, 1*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
                ]))
                elements.append(vuln_table)
                elements.append(Spacer(1, 20))
            
            # Privacy Issues Section
            if scan.privacy_issues.count() > 0:
                elements.append(Paragraph("Privacy Issues Detected", self.styles['SectionHeader']))
                
                privacy_data = [['ID', 'Name', 'Severity', 'Impact']]
                for issue in scan.privacy_issues.all():
                    privacy_data.append([
                        str(issue.id),
                        issue.name[:40] + '...' if len(issue.name) > 40 else issue.name,
                        issue.severity.upper(),
                        issue.privacy_impact[:20] + '...' if len(issue.privacy_impact) > 20 else issue.privacy_impact
                    ])
                
                privacy_table = Table(privacy_data, colWidths=[0.5*inch, 3*inch, 1.2*inch, 1*inch])
                privacy_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f59e0b')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
                ]))
                elements.append(privacy_table)
                elements.append(Spacer(1, 20))
            
            # Recommendations
            elements.append(Paragraph("Recommendations", self.styles['SectionHeader']))
            recommendations = self._generate_recommendations(scan)
            for i, rec in enumerate(recommendations, 1):
                elements.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
                elements.append(Spacer(1, 6))
            
            # Build PDF
            doc.build(elements)
            buffer.seek(0)
            return buffer
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            raise
    
    def export_to_csv(self, scan, report_data):
        """
        Generate CSV report
        
        Args:
            scan: Scan object
            report_data: Dictionary containing report data
        
        Returns:
            StringIO: CSV file buffer
        """
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header information
            writer.writerow(['PrivIoT Security Report'])
            writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow([])
            
            # Scan metadata
            writer.writerow(['Scan Information'])
            writer.writerow(['Scan ID', scan.id])
            writer.writerow(['Scan Date', scan.scan_date.strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow(['Device Name', scan.device.name])
            writer.writerow(['Device Type', scan.device.device_type or 'Unknown'])
            writer.writerow(['Manufacturer', scan.device.manufacturer or 'Unknown'])
            writer.writerow(['IP Address', scan.device.ip_address or 'N/A'])
            writer.writerow(['MAC Address', scan.device.mac_address or 'N/A'])
            writer.writerow([])
            
            # Scores
            writer.writerow(['Security Scores'])
            writer.writerow(['Metric', 'Score', 'Risk Level'])
            writer.writerow(['Overall Score', f"{scan.overall_score:.1f}/10", scan.risk_level])
            writer.writerow(['Security Score', f"{scan.security_score:.1f}/10", self._get_risk_level(scan.security_score)])
            writer.writerow(['Privacy Score', f"{scan.privacy_score:.1f}/10", self._get_risk_level(scan.privacy_score)])
            writer.writerow([])
            
            # Vulnerabilities
            writer.writerow(['Vulnerabilities'])
            writer.writerow(['ID', 'Name', 'Severity', 'CVSS Score', 'Status', 'Description'])
            for vuln in scan.vulnerabilities.all():
                writer.writerow([
                    vuln.id,
                    vuln.name,
                    vuln.severity,
                    vuln.cvss_score,
                    vuln.status,
                    vuln.description
                ])
            writer.writerow([])
            
            # Privacy Issues
            writer.writerow(['Privacy Issues'])
            writer.writerow(['ID', 'Name', 'Severity', 'Impact', 'Status', 'Description'])
            for issue in scan.privacy_issues.all():
                writer.writerow([
                    issue.id,
                    issue.name,
                    issue.severity,
                    issue.privacy_impact,
                    issue.status,
                    issue.description
                ])
            
            return output.getvalue()
            
        except Exception as e:
            logger.error(f"Error generating CSV report: {str(e)}")
            raise
    
    def export_to_json(self, scan, report_data):
        """
        Generate JSON report
        
        Args:
            scan: Scan object
            report_data: Dictionary containing report data
        
        Returns:
            str: JSON formatted report
        """
        try:
            export_data = {
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'scan_id': scan.id,
                    'scan_date': scan.scan_date.isoformat(),
                    'report_version': '1.0'
                },
                'device': {
                    'id': scan.device.id,
                    'name': scan.device.name,
                    'type': scan.device.device_type,
                    'manufacturer': scan.device.manufacturer,
                    'model': scan.device.model,
                    'firmware_version': scan.device.firmware_version,
                    'ip_address': scan.device.ip_address,
                    'mac_address': scan.device.mac_address,
                    'location': scan.device.location
                },
                'security_assessment': {
                    'overall_score': float(scan.overall_score) if scan.overall_score else 0.0,
                    'security_score': float(scan.security_score) if scan.security_score else 0.0,
                    'privacy_score': float(scan.privacy_score) if scan.privacy_score else 0.0,
                    'risk_level': scan.risk_level,
                    'scan_duration': float(scan.scan_duration) if scan.scan_duration else 0.0
                },
                'vulnerabilities': [
                    {
                        'id': vuln.id,
                        'name': vuln.name,
                        'description': vuln.description,
                        'severity': vuln.severity,
                        'cvss_score': float(vuln.cvss_score) if vuln.cvss_score else 0.0,
                        'cvss_vector': vuln.cvss_vector,
                        'cwe_id': vuln.cwe_id,
                        'status': vuln.status,
                        'discovered_date': vuln.discovered_date.isoformat() if vuln.discovered_date else None,
                        'recommendation': vuln.recommendation
                    }
                    for vuln in scan.vulnerabilities.all()
                ],
                'privacy_issues': [
                    {
                        'id': issue.id,
                        'name': issue.name,
                        'description': issue.description,
                        'severity': issue.severity,
                        'privacy_impact': issue.privacy_impact,
                        'data_collected': issue.data_collected,
                        'status': issue.status,
                        'recommendation': issue.recommendation
                    }
                    for issue in scan.privacy_issues.all()
                ],
                'recommendations': self._generate_recommendations(scan)
            }
            
            return json.dumps(export_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error generating JSON report: {str(e)}")
            raise
    
    def _get_risk_level(self, score):
        """Determine risk level from score"""
        if score >= 8.0:
            return 'Low'
        elif score >= 6.0:
            return 'Medium'
        elif score >= 4.0:
            return 'High'
        else:
            return 'Critical'
    
    def _generate_recommendations(self, scan):
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Check for critical vulnerabilities
        critical_vulns = [v for v in scan.vulnerabilities.all() if v.severity == 'critical']
        if critical_vulns:
            recommendations.append(
                f"Immediately address {len(critical_vulns)} critical vulnerabilities. "
                "These pose severe security risks and should be patched urgently."
            )
        
        # Check for high severity issues
        high_vulns = [v for v in scan.vulnerabilities.all() if v.severity == 'high']
        if high_vulns:
            recommendations.append(
                f"Address {len(high_vulns)} high-severity vulnerabilities within 30 days."
            )
        
        # Privacy recommendations
        privacy_issues = scan.privacy_issues.count()
        if privacy_issues > 0:
            recommendations.append(
                f"Review and address {privacy_issues} privacy concerns. "
                "Ensure data collection practices comply with relevant regulations."
            )
        
        # Firmware update recommendation
        if scan.device.firmware_version:
            recommendations.append(
                "Ensure device firmware is up to date. Check manufacturer website for latest version."
            )
        
        # Network segmentation
        if scan.security_score < 7.0:
            recommendations.append(
                "Consider isolating this device on a separate network segment (VLAN) "
                "to limit potential attack surface."
            )
        
        # General security
        recommendations.extend([
            "Enable automatic security updates if available.",
            "Use strong, unique passwords for device administration.",
            "Disable unnecessary services and ports.",
            "Implement network monitoring to detect unusual traffic patterns.",
            "Review and restrict device permissions and access controls."
        ])
        
        return recommendations[:10]  # Return top 10 recommendations


# Global instance
report_exporter = ReportExporter()
