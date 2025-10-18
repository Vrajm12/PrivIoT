"""
Trend Analysis Module - Analyze security trends over time
"""
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List
from sqlalchemy import func
from extensions import db
from models import Scan, Device, Vulnerability

logger = logging.getLogger(__name__)


class TrendAnalyzer:
    """Analyze security trends and patterns"""
    
    def analyze_device_trends(self, device_id: int, days: int = 30) -> Dict:
        """
        Analyze security trends for a specific device
        
        Args:
            device_id: Device ID to analyze
            days: Number of days to analyze
        
        Returns:
            Dictionary containing trend analysis
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Get all scans for this device in the time period
            scans = Scan.query.filter(
                Scan.device_id == device_id,
                Scan.scan_date >= cutoff_date,
                Scan.status == 'completed'
            ).order_by(Scan.scan_date.asc()).all()
            
            if not scans:
                return {
                    'error': 'No scan data available for the specified period',
                    'device_id': device_id
                }
            
            # Analyze trends
            trend_data = {
                'device_id': device_id,
                'analysis_period_days': days,
                'total_scans': len(scans),
                'first_scan_date': scans[0].scan_date.isoformat(),
                'last_scan_date': scans[-1].scan_date.isoformat(),
                'score_trends': self._analyze_score_trends(scans),
                'vulnerability_trends': self._analyze_vulnerability_trends(scans),
                'risk_evolution': self._analyze_risk_evolution(scans),
                'recommendations': self._generate_trend_recommendations(scans)
            }
            
            return trend_data
            
        except Exception as e:
            logger.error(f"Error analyzing device trends: {str(e)}")
            return {'error': str(e)}
    
    def analyze_global_trends(self, user_id: int, days: int = 30) -> Dict:
        """
        Analyze security trends across all user devices
        
        Args:
            user_id: User ID
            days: Number of days to analyze
        
        Returns:
            Dictionary containing global trend analysis
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Get all user devices
            devices = Device.query.filter_by(user_id=user_id).all()
            
            if not devices:
                return {'error': 'No devices found for this user'}
            
            # Get all scans for user's devices
            device_ids = [d.id for d in devices]
            scans = Scan.query.filter(
                Scan.device_id.in_(device_ids),
                Scan.scan_date >= cutoff_date,
                Scan.status == 'completed'
            ).order_by(Scan.scan_date.asc()).all()
            
            if not scans:
                return {'error': 'No scan data available'}
            
            global_trends = {
                'user_id': user_id,
                'analysis_period_days': days,
                'total_devices': len(devices),
                'total_scans': len(scans),
                'device_summary': self._summarize_devices(devices),
                'average_scores': self._calculate_average_scores(scans),
                'vulnerability_statistics': self._global_vulnerability_stats(scans),
                'risk_distribution': self._calculate_risk_distribution(scans),
                'most_vulnerable_devices': self._identify_vulnerable_devices(devices),
                'improvement_opportunities': self._identify_improvements(devices, scans)
            }
            
            return global_trends
            
        except Exception as e:
            logger.error(f"Error analyzing global trends: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_score_trends(self, scans: List[Scan]) -> Dict:
        """Analyze how security scores change over time"""
        score_data = {
            'security_scores': [],
            'privacy_scores': [],
            'overall_scores': [],
            'dates': [],
            'trend_direction': {}
        }
        
        for scan in scans:
            score_data['dates'].append(scan.scan_date.isoformat())
            score_data['security_scores'].append(float(scan.security_score or 0))
            score_data['privacy_scores'].append(float(scan.privacy_score or 0))
            score_data['overall_scores'].append(float(scan.overall_score or 0))
        
        # Calculate trend direction
        if len(scans) >= 2:
            score_data['trend_direction'] = {
                'security': self._calculate_trend_direction(score_data['security_scores']),
                'privacy': self._calculate_trend_direction(score_data['privacy_scores']),
                'overall': self._calculate_trend_direction(score_data['overall_scores'])
            }
        
        # Calculate averages
        score_data['averages'] = {
            'security': sum(score_data['security_scores']) / len(score_data['security_scores']),
            'privacy': sum(score_data['privacy_scores']) / len(score_data['privacy_scores']),
            'overall': sum(score_data['overall_scores']) / len(score_data['overall_scores'])
        }
        
        return score_data
    
    def _analyze_vulnerability_trends(self, scans: List[Scan]) -> Dict:
        """Analyze vulnerability trends"""
        vuln_data = {
            'total_by_scan': [],
            'by_severity': defaultdict(list),
            'dates': []
        }
        
        for scan in scans:
            vuln_data['dates'].append(scan.scan_date.isoformat())
            
            vulns = scan.vulnerabilities.all()
            vuln_data['total_by_scan'].append(len(vulns))
            
            # Count by severity
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for vuln in vulns:
                if vuln.severity in severity_counts:
                    severity_counts[vuln.severity] += 1
            
            for severity, count in severity_counts.items():
                vuln_data['by_severity'][severity].append(count)
        
        # Calculate vulnerability resolution rate
        if len(scans) >= 2:
            first_scan_vulns = scans[0].vulnerabilities.count()
            last_scan_vulns = scans[-1].vulnerabilities.count()
            
            if first_scan_vulns > 0:
                vuln_data['resolution_rate'] = (
                    (first_scan_vulns - last_scan_vulns) / first_scan_vulns * 100
                )
            else:
                vuln_data['resolution_rate'] = 0
        
        return dict(vuln_data)
    
    def _analyze_risk_evolution(self, scans: List[Scan]) -> Dict:
        """Analyze how risk level evolves"""
        risk_evolution = {
            'timeline': [],
            'changes': []
        }
        
        prev_risk = None
        for scan in scans:
            risk_evolution['timeline'].append({
                'date': scan.scan_date.isoformat(),
                'risk_level': scan.risk_level,
                'overall_score': float(scan.overall_score or 0)
            })
            
            if prev_risk and prev_risk != scan.risk_level:
                risk_evolution['changes'].append({
                    'date': scan.scan_date.isoformat(),
                    'from': prev_risk,
                    'to': scan.risk_level,
                    'direction': 'improved' if self._risk_rank(scan.risk_level) < self._risk_rank(prev_risk) else 'worsened'
                })
            
            prev_risk = scan.risk_level
        
        return risk_evolution
    
    def _generate_trend_recommendations(self, scans: List[Scan]) -> List[str]:
        """Generate recommendations based on trends"""
        recommendations = []
        
        if len(scans) < 2:
            recommendations.append("Continue regular scanning to establish trend baseline.")
            return recommendations
        
        # Analyze score trends
        recent_scores = [float(s.overall_score or 0) for s in scans[-3:]]
        avg_recent = sum(recent_scores) / len(recent_scores)
        
        older_scores = [float(s.overall_score or 0) for s in scans[:3]]
        avg_older = sum(older_scores) / len(older_scores)
        
        if avg_recent < avg_older:
            recommendations.append(
                "⚠️ Security posture is declining. Immediate attention required to address new vulnerabilities."
            )
        elif avg_recent > avg_older + 1:
            recommendations.append(
                "✅ Security posture is improving! Continue current remediation efforts."
            )
        
        # Check vulnerability trend
        recent_vulns = sum(s.vulnerabilities.count() for s in scans[-3:]) / min(3, len(scans))
        if recent_vulns > 5:
            recommendations.append(
                f"High vulnerability count ({recent_vulns:.0f} avg). Prioritize patch management."
            )
        
        # Check scan frequency
        if len(scans) < 4:
            recommendations.append(
                "Increase scan frequency to at least weekly for better security monitoring."
            )
        
        return recommendations
    
    def _summarize_devices(self, devices: List[Device]) -> Dict:
        """Summarize device information"""
        device_types = defaultdict(int)
        manufacturers = defaultdict(int)
        
        for device in devices:
            device_types[device.device_type or 'Unknown'] += 1
            manufacturers[device.manufacturer or 'Unknown'] += 1
        
        return {
            'by_type': dict(device_types),
            'by_manufacturer': dict(manufacturers),
            'total': len(devices)
        }
    
    def _calculate_average_scores(self, scans: List[Scan]) -> Dict:
        """Calculate average scores across all scans"""
        if not scans:
            return {}
        
        return {
            'security': sum(float(s.security_score or 0) for s in scans) / len(scans),
            'privacy': sum(float(s.privacy_score or 0) for s in scans) / len(scans),
            'overall': sum(float(s.overall_score or 0) for s in scans) / len(scans)
        }
    
    def _global_vulnerability_stats(self, scans: List[Scan]) -> Dict:
        """Calculate global vulnerability statistics"""
        total_vulns = 0
        by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for scan in scans:
            for vuln in scan.vulnerabilities.all():
                total_vulns += 1
                if vuln.severity in by_severity:
                    by_severity[vuln.severity] += 1
        
        return {
            'total': total_vulns,
            'by_severity': by_severity,
            'average_per_scan': total_vulns / len(scans) if scans else 0
        }
    
    def _calculate_risk_distribution(self, scans: List[Scan]) -> Dict:
        """Calculate risk level distribution"""
        risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for scan in scans:
            if scan.risk_level in risk_counts:
                risk_counts[scan.risk_level] += 1
        
        return risk_counts
    
    def _identify_vulnerable_devices(self, devices: List[Device]) -> List[Dict]:
        """Identify most vulnerable devices"""
        device_risks = []
        
        for device in devices:
            latest_scan = device.get_latest_scan()
            if latest_scan and latest_scan.status == 'completed':
                device_risks.append({
                    'device_id': device.id,
                    'device_name': device.name,
                    'device_type': device.device_type,
                    'overall_score': float(latest_scan.overall_score or 0),
                    'risk_level': latest_scan.risk_level,
                    'vulnerability_count': latest_scan.vulnerabilities.count(),
                    'last_scan': latest_scan.scan_date.isoformat()
                })
        
        # Sort by score (ascending) to get most vulnerable first
        device_risks.sort(key=lambda x: x['overall_score'])
        
        return device_risks[:5]  # Return top 5 most vulnerable
    
    def _identify_improvements(self, devices: List[Device], scans: List[Scan]) -> List[str]:
        """Identify improvement opportunities"""
        improvements = []
        
        # Check for devices without recent scans
        outdated_devices = []
        cutoff = datetime.utcnow() - timedelta(days=7)
        
        for device in devices:
            latest_scan = device.get_latest_scan()
            if not latest_scan or latest_scan.scan_date < cutoff:
                outdated_devices.append(device.name)
        
        if outdated_devices:
            improvements.append(
                f"Update scans for {len(outdated_devices)} devices: {', '.join(outdated_devices[:3])}"
            )
        
        # Check for persistent high-risk devices
        high_risk_devices = [d for d in devices if d.get_security_status() in ['poor', 'fair']]
        if high_risk_devices:
            improvements.append(
                f"Address security issues on {len(high_risk_devices)} high-risk devices."
            )
        
        # Check for common vulnerabilities
        vuln_names = defaultdict(int)
        for scan in scans:
            for vuln in scan.vulnerabilities.all():
                vuln_names[vuln.name] += 1
        
        if vuln_names:
            most_common = sorted(vuln_names.items(), key=lambda x: x[1], reverse=True)[:3]
            improvements.append(
                f"Common vulnerabilities: {', '.join([v[0] for v in most_common])}"
            )
        
        return improvements
    
    def _calculate_trend_direction(self, values: List[float]) -> str:
        """Calculate if trend is improving, declining, or stable"""
        if len(values) < 2:
            return 'insufficient_data'
        
        # Calculate simple linear trend
        first_half = sum(values[:len(values)//2]) / (len(values)//2)
        second_half = sum(values[len(values)//2:]) / (len(values) - len(values)//2)
        
        diff = second_half - first_half
        
        if diff > 0.5:
            return 'improving'
        elif diff < -0.5:
            return 'declining'
        else:
            return 'stable'
    
    def _risk_rank(self, risk_level: str) -> int:
        """Convert risk level to numeric rank for comparison"""
        ranks = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return ranks.get(risk_level, 0)


# Global instance
trend_analyzer = TrendAnalyzer()
