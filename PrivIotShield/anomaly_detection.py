import json
import logging
import os
import random
from datetime import datetime, timedelta
import numpy as np
from openai import OpenAI
from app import app

# Configure logging
logger = logging.getLogger(__name__)

# OpenAI configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
openai = OpenAI(api_key=OPENAI_API_KEY)

# Anomaly detection thresholds
THRESHOLDS = {
    "data_transfer": {
        "low": 100,    # MB
        "medium": 500,  # MB
        "high": 2000    # MB
    },
    "connection_attempts": {
        "low": 10,
        "medium": 50,
        "high": 200
    },
    "failed_auth": {
        "low": 3,
        "medium": 10,
        "high": 20
    },
    "unusual_ports": {
        "low": 1,
        "medium": 3,
        "high": 5
    },
    "unusual_hours": {
        "start": 23,  # 11 PM
        "end": 5      # 5 AM
    }
}

class AnomalyDetector:
    """Class for detecting anomalies in IoT device behavior"""
    
    def __init__(self):
        """Initialize the anomaly detector"""
        self.detection_methods = {
            "data_transfer": self.detect_unusual_data_transfer,
            "connection_attempts": self.detect_excessive_connections,
            "failed_auth": self.detect_authentication_failures,
            "unusual_ports": self.detect_unusual_ports,
            "unusual_hours": self.detect_unusual_activity_hours,
            "pattern_change": self.detect_behavior_pattern_changes
        }
    
    def analyze_device_behavior(self, device, telemetry_data):
        """
        Analyze device behavior for anomalies
        
        Args:
            device: Device object
            telemetry_data: Recent telemetry data from the device
            
        Returns:
            list: List of detected anomalies
        """
        try:
            anomalies = []
            
            # Apply each detection method
            for method_name, detection_method in self.detection_methods.items():
                try:
                    # Skip methods that require specific data not available
                    if method_name == "pattern_change" and (not telemetry_data or len(telemetry_data) < 5):
                        continue
                        
                    anomaly = detection_method(device, telemetry_data)
                    if anomaly:
                        anomalies.append(anomaly)
                        
                except Exception as e:
                    logger.error(f"Error in anomaly detection method {method_name}: {str(e)}")
            
            # If significant anomalies detected, use AI to analyze them
            if anomalies and any(a.get('severity') in ['high', 'critical'] for a in anomalies):
                ai_analysis = self.analyze_anomalies_with_ai(device, anomalies, telemetry_data)
                if ai_analysis:
                    # Add AI insights to the most severe anomaly
                    for anomaly in anomalies:
                        if anomaly.get('severity') in ['high', 'critical']:
                            anomaly['ai_insights'] = ai_analysis
                            break
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error analyzing device behavior: {str(e)}")
            return []
    
    def detect_unusual_data_transfer(self, device, telemetry_data):
        """
        Detect unusual data transfer volumes
        
        Args:
            device: Device object
            telemetry_data: Telemetry data
            
        Returns:
            dict: Anomaly information if detected, None otherwise
        """
        # Extract data transfer information from telemetry
        if not telemetry_data or 'data_transfer' not in telemetry_data:
            return None
            
        data_transfer = telemetry_data.get('data_transfer', {})
        current_transfer = data_transfer.get('volume_mb', 0)
        average_transfer = data_transfer.get('average_mb', 0)
        
        # No baseline to compare against
        if average_transfer <= 0:
            return None
        
        # Calculate deviation percentage
        deviation = ((current_transfer - average_transfer) / average_transfer) * 100
        
        # Determine if anomalous
        if deviation > 300:  # More than 300% increase
            severity = "high"
            description = f"Excessive data transfer volume detected: {current_transfer} MB vs average {average_transfer} MB (+{deviation:.1f}%)"
            recommendation = "Investigate data exfiltration or compromised device. Consider network isolation."
        elif deviation > 150:  # More than 150% increase
            severity = "medium"
            description = f"Unusual data transfer volume detected: {current_transfer} MB vs average {average_transfer} MB (+{deviation:.1f}%)"
            recommendation = "Monitor device activity and check for unauthorized access or malware."
        elif deviation > 80:  # More than 80% increase
            severity = "low"
            description = f"Increased data transfer volume detected: {current_transfer} MB vs average {average_transfer} MB (+{deviation:.1f}%)"
            recommendation = "Review device behavior and traffic patterns."
        else:
            return None  # No anomaly detected
        
        return {
            "type": "unusual_data_transfer",
            "severity": severity,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "current_volume": current_transfer,
                "average_volume": average_transfer,
                "deviation_percent": deviation
            },
            "recommendation": recommendation
        }
    
    def detect_excessive_connections(self, device, telemetry_data):
        """
        Detect excessive connection attempts
        
        Args:
            device: Device object
            telemetry_data: Telemetry data
            
        Returns:
            dict: Anomaly information if detected, None otherwise
        """
        if not telemetry_data or 'connections' not in telemetry_data:
            return None
            
        connections = telemetry_data.get('connections', {})
        attempts = connections.get('attempts', 0)
        period_hours = connections.get('period_hours', 1)
        
        # Normalize to hourly rate for comparison
        hourly_rate = attempts / period_hours if period_hours > 0 else attempts
        
        thresholds = THRESHOLDS["connection_attempts"]
        
        if hourly_rate > thresholds["high"]:
            severity = "high"
            description = f"Excessive connection attempts detected: {attempts} in {period_hours} hour(s)"
            recommendation = "Investigate possible brute force attack or device malfunction. Consider temporary isolation."
        elif hourly_rate > thresholds["medium"]:
            severity = "medium"
            description = f"Unusual number of connection attempts: {attempts} in {period_hours} hour(s)"
            recommendation = "Monitor for potential attack patterns and verify device integrity."
        elif hourly_rate > thresholds["low"]:
            severity = "low"
            description = f"Increased connection attempts: {attempts} in {period_hours} hour(s)"
            recommendation = "Monitor device behavior for persistent pattern."
        else:
            return None
        
        return {
            "type": "excessive_connections",
            "severity": severity,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "connection_attempts": attempts,
                "period_hours": period_hours,
                "hourly_rate": hourly_rate
            },
            "recommendation": recommendation
        }
    
    def detect_authentication_failures(self, device, telemetry_data):
        """
        Detect unusual authentication failures
        
        Args:
            device: Device object
            telemetry_data: Telemetry data
            
        Returns:
            dict: Anomaly information if detected, None otherwise
        """
        if not telemetry_data or 'authentication' not in telemetry_data:
            return None
            
        auth_data = telemetry_data.get('authentication', {})
        failures = auth_data.get('failures', 0)
        period_hours = auth_data.get('period_hours', 24)
        
        thresholds = THRESHOLDS["failed_auth"]
        
        if failures > thresholds["high"]:
            severity = "critical"
            description = f"Critical: {failures} authentication failures in {period_hours} hour(s)"
            recommendation = "Possible brute force attack in progress. Implement account lockout and investigate immediately."
        elif failures > thresholds["medium"]:
            severity = "high"
            description = f"High number of authentication failures: {failures} in {period_hours} hour(s)"
            recommendation = "Investigate potential unauthorized access attempts and consider changing credentials."
        elif failures > thresholds["low"]:
            severity = "medium"
            description = f"Multiple authentication failures: {failures} in {period_hours} hour(s)"
            recommendation = "Monitor access attempts and verify legitimate usage."
        else:
            return None
        
        return {
            "type": "authentication_failures",
            "severity": severity,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "failures": failures,
                "period_hours": period_hours,
                "hourly_rate": failures / period_hours if period_hours > 0 else failures
            },
            "recommendation": recommendation
        }
    
    def detect_unusual_ports(self, device, telemetry_data):
        """
        Detect connections on unusual ports
        
        Args:
            device: Device object
            telemetry_data: Telemetry data
            
        Returns:
            dict: Anomaly information if detected, None otherwise
        """
        if not telemetry_data or 'network' not in telemetry_data:
            return None
            
        network_data = telemetry_data.get('network', {})
        active_ports = network_data.get('active_ports', [])
        expected_ports = network_data.get('expected_ports', [])
        
        # Find unexpected ports
        unexpected_ports = [p for p in active_ports if p not in expected_ports]
        
        num_unexpected = len(unexpected_ports)
        thresholds = THRESHOLDS["unusual_ports"]
        
        if num_unexpected > thresholds["high"]:
            severity = "critical"
            description = f"Multiple unexpected ports active: {', '.join(map(str, unexpected_ports))}"
            recommendation = "Possible compromise or malware. Isolate device immediately and investigate."
        elif num_unexpected > thresholds["medium"]:
            severity = "high"
            description = f"Several unexpected ports active: {', '.join(map(str, unexpected_ports))}"
            recommendation = "Investigate for unauthorized services or malware. Consider temporary isolation."
        elif num_unexpected > thresholds["low"]:
            severity = "medium"
            description = f"Unexpected ports active: {', '.join(map(str, unexpected_ports))}"
            recommendation = "Verify if these ports should be active and check device configuration."
        else:
            return None
        
        return {
            "type": "unusual_ports",
            "severity": severity,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "unexpected_ports": unexpected_ports,
                "expected_ports": expected_ports
            },
            "recommendation": recommendation
        }
    
    def detect_unusual_activity_hours(self, device, telemetry_data):
        """
        Detect activity during unusual hours
        
        Args:
            device: Device object
            telemetry_data: Telemetry data
            
        Returns:
            dict: Anomaly information if detected, None otherwise
        """
        if not telemetry_data or 'activity' not in telemetry_data:
            return None
            
        activity_data = telemetry_data.get('activity', {})
        current_hour = datetime.utcnow().hour
        activity_level = activity_data.get('level', 0)  # 0-10 scale
        
        # Check if current time is within unusual hours
        unusual_hours = THRESHOLDS["unusual_hours"]
        is_unusual_hour = current_hour >= unusual_hours["start"] or current_hour < unusual_hours["end"]
        
        if not is_unusual_hour or activity_level < 3:
            return None
        
        if activity_level > 7:
            severity = "high"
            description = f"High activity level ({activity_level}/10) during unusual hours ({current_hour}:00 UTC)"
            recommendation = "Investigate potential unauthorized usage or automated process."
        elif activity_level > 5:
            severity = "medium"
            description = f"Moderate activity level ({activity_level}/10) during unusual hours ({current_hour}:00 UTC)"
            recommendation = "Verify expected behavior and scheduled tasks."
        else:
            severity = "low"
            description = f"Unusual hour activity ({activity_level}/10) at {current_hour}:00 UTC"
            recommendation = "Monitor for persistent pattern."
        
        return {
            "type": "unusual_hours_activity",
            "severity": severity,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "hour": current_hour,
                "activity_level": activity_level
            },
            "recommendation": recommendation
        }
    
    def detect_behavior_pattern_changes(self, device, telemetry_data):
        """
        Detect changes in behavior patterns using historical data
        
        Args:
            device: Device object
            telemetry_data: Telemetry data including historical patterns
            
        Returns:
            dict: Anomaly information if detected, None otherwise
        """
        if not telemetry_data or 'historical' not in telemetry_data or 'current' not in telemetry_data:
            return None
            
        historical = telemetry_data.get('historical', {})
        current = telemetry_data.get('current', {})
        
        # Extract relevant metrics for comparison
        metrics = ['bandwidth_usage', 'connection_frequency', 'packet_size', 'protocol_distribution']
        changes = []
        
        for metric in metrics:
            if metric in historical and metric in current:
                hist_value = historical.get(metric)
                curr_value = current.get(metric)
                
                # Skip metrics with missing data
                if hist_value is None or curr_value is None:
                    continue
                    
                # Calculate change percentage
                if isinstance(hist_value, (int, float)) and isinstance(curr_value, (int, float)) and hist_value > 0:
                    change_pct = ((curr_value - hist_value) / hist_value) * 100
                    if abs(change_pct) > 50:  # Significant change threshold
                        changes.append({
                            "metric": metric,
                            "historical": hist_value,
                            "current": curr_value,
                            "change_percent": change_pct
                        })
        
        if not changes:
            return None
            
        # Determine severity based on number and magnitude of changes
        num_changes = len(changes)
        avg_change = sum(abs(c["change_percent"]) for c in changes) / num_changes if num_changes > 0 else 0
        
        if num_changes > 3 or avg_change > 200:
            severity = "high"
            description = f"Major behavior pattern changes detected across {num_changes} metrics"
            recommendation = "Investigate potential compromise or significant configuration change."
        elif num_changes > 2 or avg_change > 100:
            severity = "medium"
            description = f"Significant behavior pattern changes detected in {num_changes} metrics"
            recommendation = "Review recent device changes and monitor for persistent abnormal behavior."
        else:
            severity = "low"
            description = f"Behavior pattern changes detected in {num_changes} metrics"
            recommendation = "Monitor for continued pattern deviation."
        
        return {
            "type": "behavior_pattern_change",
            "severity": severity,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "changed_metrics": changes,
                "total_metrics_analyzed": len(metrics),
                "avg_change_percent": avg_change
            },
            "recommendation": recommendation
        }
    
    def analyze_anomalies_with_ai(self, device, anomalies, telemetry_data):
        """
        Use AI to analyze detected anomalies for deeper insights
        
        Args:
            device: Device object
            anomalies: List of detected anomalies
            telemetry_data: Telemetry data
            
        Returns:
            dict: AI analysis results
        """
        if not OPENAI_API_KEY or not openai:
            logger.warning("OpenAI API not configured. Skipping AI analysis of anomalies.")
            return None
            
        try:
            # Prepare data for AI analysis
            device_data = {
                "id": device.id,
                "name": device.name,
                "type": device.device_type,
                "manufacturer": device.manufacturer,
                "model": device.model,
                "firmware_version": device.firmware_version
            }
            
            # Create prompt
            anomalies_json = json.dumps(anomalies, indent=2)
            telemetry_sample = json.dumps({k: v for k, v in telemetry_data.items() if k != 'historical'}, indent=2)
            
            prompt = f"""
            Analyze these anomalies detected in an IoT device and provide security insights:
            
            Device Information:
            - Name: {device.name}
            - Type: {device.device_type}
            - Manufacturer: {device.manufacturer}
            - Model: {device.model}
            - Firmware: {device.firmware_version}
            
            Detected Anomalies:
            {anomalies_json}
            
            Current Telemetry Sample:
            {telemetry_sample}
            
            Provide a security analysis with:
            1. Potential attack vectors or security incidents these anomalies might indicate
            2. Common IoT vulnerabilities that might be being exploited
            3. Severity assessment and risk evaluation
            4. Specific actionable recommendations for mitigation
            
            Format your response as JSON with these fields:
            - potential_threats: array of potential threat scenarios
            - exploit_vectors: array of possible exploit methods
            - severity_assessment: text assessment of overall severity
            - mitigation_steps: array of specific actions to take
            """
            
            response = openai.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are an IoT security expert analyzing device anomalies and providing threat intelligence insights."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.3
            )
            
            result = json.loads(response.choices[0].message.content)
            logger.info(f"AI analysis completed for anomalies in device {device.id}")
            return result
        
        except Exception as e:
            logger.error(f"Error in AI analysis of anomalies: {str(e)}")
            return None
            
    def get_sample_telemetry(self, device_id):
        """
        Generate sample telemetry data for simulation purposes
        In a real implementation, this would be actual device telemetry
        
        Args:
            device_id: Device ID
            
        Returns:
            dict: Sample telemetry data
        """
        # This method simulates telemetry for demonstration
        # In a production system, this would be real device data
        
        # Generate base telemetry with normal patterns
        base_telemetry = {
            "data_transfer": {
                "volume_mb": random.uniform(50, 150),
                "average_mb": 100,
                "upload_mb": random.uniform(10, 50),
                "download_mb": random.uniform(40, 100)
            },
            "connections": {
                "attempts": random.randint(5, 15),
                "period_hours": 1,
                "successful": random.randint(5, 15),
                "sources": random.randint(1, 3)
            },
            "authentication": {
                "failures": random.randint(0, 2),
                "period_hours": 24,
                "successes": random.randint(5, 10)
            },
            "network": {
                "active_ports": [80, 443, 8080],
                "expected_ports": [80, 443, 8080, 22],
                "protocols": ["HTTP", "HTTPS", "MQTT"],
                "connections_per_hour": random.randint(10, 50)
            },
            "activity": {
                "level": random.uniform(0, 10),
                "last_active": (datetime.utcnow() - timedelta(minutes=random.randint(5, 60))).isoformat(),
                "avg_daily_hours": random.uniform(4, 12)
            },
            "historical": {
                "bandwidth_usage": 85.5,
                "connection_frequency": 27,
                "packet_size": 1280,
                "protocol_distribution": {"HTTP": 0.2, "HTTPS": 0.7, "MQTT": 0.1}
            },
            "current": {
                "bandwidth_usage": random.uniform(70, 100),
                "connection_frequency": random.randint(20, 35),
                "packet_size": random.randint(1024, 1536),
                "protocol_distribution": {"HTTP": random.uniform(0.1, 0.3), "HTTPS": random.uniform(0.6, 0.8), "MQTT": random.uniform(0.05, 0.15)}
            }
        }
        
        # Randomly introduce anomalies (20% chance)
        if random.random() < 0.2:
            anomaly_type = random.choice([
                "data_transfer", "connections", "auth_failures", 
                "unusual_ports", "unusual_hours", "pattern_change"
            ])
            
            if anomaly_type == "data_transfer":
                # Simulate abnormally high data transfer
                base_telemetry["data_transfer"]["volume_mb"] = random.uniform(300, 1000)
                
            elif anomaly_type == "connections":
                # Simulate excessive connection attempts
                base_telemetry["connections"]["attempts"] = random.randint(100, 500)
                
            elif anomaly_type == "auth_failures":
                # Simulate high number of authentication failures
                base_telemetry["authentication"]["failures"] = random.randint(15, 50)
                
            elif anomaly_type == "unusual_ports":
                # Simulate unexpected open ports
                base_telemetry["network"]["active_ports"] = [80, 443, 8080, 4444, 5555, 6666]
                
            elif anomaly_type == "unusual_hours":
                # Simulate activity during unusual hours
                base_telemetry["activity"]["level"] = random.uniform(7, 10)
                
            elif anomaly_type == "pattern_change":
                # Simulate significant behavior pattern changes
                base_telemetry["current"]["bandwidth_usage"] = base_telemetry["historical"]["bandwidth_usage"] * random.uniform(2, 5)
                base_telemetry["current"]["connection_frequency"] = base_telemetry["historical"]["connection_frequency"] * random.uniform(2, 4)
        
        return base_telemetry


# Initialize anomaly detector
anomaly_detector = AnomalyDetector()

def detect_anomalies(device):
    """
    Detect anomalies for a specific device
    
    Args:
        device: Device object
        
    Returns:
        list: Detected anomalies
    """
    try:
        # In a real implementation, get actual telemetry from device or monitoring system
        # For demonstration, use sample telemetry
        telemetry = anomaly_detector.get_sample_telemetry(device.id)
        
        # Analyze for anomalies
        anomalies = anomaly_detector.analyze_device_behavior(device, telemetry)
        
        logger.info(f"Anomaly detection completed for device {device.id}: {len(anomalies)} anomalies found")
        return anomalies
        
    except Exception as e:
        logger.error(f"Error in anomaly detection for device {device.id}: {str(e)}")
        return []