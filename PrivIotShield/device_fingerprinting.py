import os
import json
import logging
import hashlib
from datetime import datetime
from openai import OpenAI
from app import app

# Configure logging
logger = logging.getLogger(__name__)

# OpenAI configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
openai = OpenAI(api_key=OPENAI_API_KEY)

class DeviceFingerprinter:
    """
    Class for generating and analyzing device fingerprints to identify unknown devices
    and detect unauthorized or counterfeit devices on the network.
    """
    
    def __init__(self):
        """Initialize the device fingerprinter"""
        self.known_profiles = self.load_device_profiles()
    
    def load_device_profiles(self):
        """
        Load known device profiles from database or file
        
        Returns:
            dict: Device profiles by manufacturer and model
        """
        try:
            # In a real implementation, this would load from a database
            # For now, return a sample set of profiles
            return {
                "amazon": {
                    "echo": {
                        "ports": [80, 443, 8080, 4070, 5000],
                        "protocols": ["HTTP", "HTTPS", "MQTT"],
                        "user_agents": ["Mozilla/5.0 (Echo)", "AmazonEchoApp"],
                        "certificate_patterns": ["Amazon Services LLC", "*.amazonaws.com"],
                        "traffic_patterns": {
                            "idle_bandwidth": "0.01-0.1",  # MB/hour
                            "active_bandwidth": "1-10",    # MB/hour
                            "typical_destinations": ["amazonaws.com", "amazon.com"]
                        }
                    }
                },
                "google": {
                    "nest": {
                        "ports": [80, 443, 9000],
                        "protocols": ["HTTP", "HTTPS", "QUIC"],
                        "user_agents": ["Nest Device", "GoogleNest"],
                        "certificate_patterns": ["Google LLC", "*.google.com"],
                        "traffic_patterns": {
                            "idle_bandwidth": "0.05-0.2",  # MB/hour
                            "active_bandwidth": "2-15",    # MB/hour
                            "typical_destinations": ["google.com", "googleapis.com"]
                        }
                    }
                },
                "generic": {
                    "ip_camera": {
                        "ports": [80, 443, 554, 1935, 8000],
                        "protocols": ["HTTP", "HTTPS", "RTSP", "RTMP"],
                        "user_agents": ["IP Camera", "Generic Camera"],
                        "certificate_patterns": ["Self-signed", "*.local"],
                        "traffic_patterns": {
                            "idle_bandwidth": "0.1-1",     # MB/hour
                            "active_bandwidth": "10-100",  # MB/hour
                            "typical_destinations": ["local network", "dynamic DNS"]
                        }
                    },
                    "smart_bulb": {
                        "ports": [80, 443, 1883],
                        "protocols": ["HTTP", "HTTPS", "MQTT"],
                        "user_agents": ["Smart Light", "IoT Bulb"],
                        "certificate_patterns": ["Self-signed", "*.local"],
                        "traffic_patterns": {
                            "idle_bandwidth": "0.001-0.01",  # MB/hour
                            "active_bandwidth": "0.01-0.1",  # MB/hour
                            "typical_destinations": ["local network", "manufacturer cloud"]
                        }
                    }
                }
            }
        except Exception as e:
            logger.error(f"Error loading device profiles: {str(e)}")
            return {}
    
    def fingerprint_device(self, device, network_data=None):
        """
        Generate a fingerprint for a device based on its behavior and characteristics
        
        Args:
            device: Device object
            network_data: Additional network behavior data if available
            
        Returns:
            dict: Device fingerprint
        """
        try:
            # Basic information from device object
            fingerprint = {
                "device_id": device.id,
                "mac_address": device.mac_address,
                "ip_address": device.ip_address,
                "reported_manufacturer": device.manufacturer,
                "reported_model": device.model,
                "reported_firmware": device.firmware_version,
                "fingerprint_time": datetime.utcnow().isoformat(),
                "network_characteristics": {}
            }
            
            # Add network characteristics if available
            if network_data:
                fingerprint["network_characteristics"] = {
                    "active_ports": network_data.get("active_ports", []),
                    "protocols": network_data.get("protocols", []),
                    "user_agent": network_data.get("user_agent", "Unknown"),
                    "certificate_info": network_data.get("certificate_info", {}),
                    "traffic_pattern": {
                        "avg_bandwidth": network_data.get("avg_bandwidth", 0),
                        "destinations": network_data.get("destinations", []),
                        "connection_frequency": network_data.get("connection_frequency", 0)
                    }
                }
            
            # Generate fingerprint hash
            fingerprint_str = json.dumps(fingerprint, sort_keys=True)
            fingerprint_hash = hashlib.sha256(fingerprint_str.encode()).hexdigest()
            fingerprint["fingerprint_hash"] = fingerprint_hash
            
            logger.info(f"Generated fingerprint for device {device.id}: {fingerprint_hash[:8]}...")
            return fingerprint
            
        except Exception as e:
            logger.error(f"Error generating device fingerprint: {str(e)}")
            return {
                "device_id": device.id,
                "fingerprint_time": datetime.utcnow().isoformat(),
                "error": str(e)
            }
    
    def match_device_profile(self, fingerprint):
        """
        Match device fingerprint against known profiles
        
        Args:
            fingerprint: Device fingerprint
            
        Returns:
            dict: Matching results including confidence and potential identity
        """
        try:
            if not fingerprint or "network_characteristics" not in fingerprint:
                return {
                    "match_found": False,
                    "confidence": 0,
                    "message": "Insufficient fingerprint data for matching"
                }
            
            # Extract characteristics for matching
            network = fingerprint.get("network_characteristics", {})
            active_ports = set(network.get("active_ports", []))
            protocols = set(network.get("protocols", []))
            user_agent = network.get("user_agent", "")
            certificate_info = network.get("certificate_info", {})
            
            best_match = None
            best_confidence = 0
            best_manufacturer = None
            best_model = None
            
            # Compare against known profiles
            for manufacturer, models in self.known_profiles.items():
                for model, profile in models.items():
                    # Calculate match percentage
                    confidence = 0
                    matches = 0
                    total_checks = 0
                    
                    # Check ports
                    profile_ports = set(profile.get("ports", []))
                    if profile_ports and active_ports:
                        port_overlap = len(active_ports.intersection(profile_ports))
                        port_match = port_overlap / max(len(profile_ports), 1)
                        confidence += port_match * 30  # Ports are 30% of the confidence
                        matches += 1 if port_match > 0.5 else 0
                        total_checks += 1
                    
                    # Check protocols
                    profile_protocols = set(profile.get("protocols", []))
                    if profile_protocols and protocols:
                        protocol_overlap = len(protocols.intersection(profile_protocols))
                        protocol_match = protocol_overlap / max(len(profile_protocols), 1)
                        confidence += protocol_match * 20  # Protocols are 20% of the confidence
                        matches += 1 if protocol_match > 0.5 else 0
                        total_checks += 1
                    
                    # Check user agent
                    profile_agents = profile.get("user_agents", [])
                    if profile_agents and user_agent:
                        agent_match = any(agent.lower() in user_agent.lower() for agent in profile_agents)
                        confidence += 15 if agent_match else 0  # User agent is 15% of the confidence
                        matches += 1 if agent_match else 0
                        total_checks += 1
                    
                    # Check certificate patterns
                    profile_cert_patterns = profile.get("certificate_patterns", [])
                    if profile_cert_patterns and certificate_info:
                        cert_subject = certificate_info.get("subject", "")
                        cert_issuer = certificate_info.get("issuer", "")
                        cert_match = any(pattern.lower() in cert_subject.lower() or 
                                        pattern.lower() in cert_issuer.lower() 
                                        for pattern in profile_cert_patterns)
                        confidence += 25 if cert_match else 0  # Certificate is 25% of the confidence
                        matches += 1 if cert_match else 0
                        total_checks += 1
                    
                    # Check traffic patterns - more complex, skipped for simplicity
                    confidence += 10  # Traffic patterns are 10% of the confidence
                    
                    # Normalize confidence by number of checks
                    normalized_confidence = confidence / 100 if total_checks > 0 else 0
                    
                    # Update best match if this is better
                    if normalized_confidence > best_confidence:
                        best_confidence = normalized_confidence
                        best_match = profile
                        best_manufacturer = manufacturer
                        best_model = model
            
            # Determine match result
            if best_confidence >= 0.7:
                match_result = {
                    "match_found": True,
                    "confidence": round(best_confidence * 100, 1),
                    "identified_manufacturer": best_manufacturer,
                    "identified_model": best_model,
                    "reported_manufacturer": fingerprint.get("reported_manufacturer", "Unknown"),
                    "reported_model": fingerprint.get("reported_model", "Unknown"),
                    "discrepancy": best_manufacturer.lower() != fingerprint.get("reported_manufacturer", "").lower() or
                                   best_model.lower() != fingerprint.get("reported_model", "").lower()
                }
            else:
                match_result = {
                    "match_found": False,
                    "confidence": round(best_confidence * 100, 1),
                    "message": "No strong match found in known profiles",
                    "best_guess_manufacturer": best_manufacturer if best_confidence > 0.4 else None,
                    "best_guess_model": best_model if best_confidence > 0.4 else None
                }
                
            logger.info(f"Profile matching for device {fingerprint.get('device_id')}: Match found: {match_result['match_found']}, Confidence: {match_result['confidence']}%")
            return match_result
            
        except Exception as e:
            logger.error(f"Error matching device profile: {str(e)}")
            return {
                "match_found": False,
                "confidence": 0,
                "error": str(e)
            }
    
    def analyze_with_ai(self, fingerprint, match_result=None):
        """
        Use AI to analyze device fingerprint for enhanced identification and security analysis
        
        Args:
            fingerprint: Device fingerprint
            match_result: Optional profile matching result
            
        Returns:
            dict: AI analysis results
        """
        if not OPENAI_API_KEY or not openai:
            logger.warning("OpenAI API not configured. Skipping AI analysis of device fingerprint.")
            return None
        
        try:
            # Prepare fingerprint data for AI
            fingerprint_data = {
                "device_id": fingerprint.get("device_id"),
                "mac_address": fingerprint.get("mac_address"),
                "ip_address": fingerprint.get("ip_address"),
                "reported_manufacturer": fingerprint.get("reported_manufacturer"),
                "reported_model": fingerprint.get("reported_model"),
                "reported_firmware": fingerprint.get("reported_firmware"),
                "network_characteristics": fingerprint.get("network_characteristics", {})
            }
            
            # Create prompt
            fingerprint_json = json.dumps(fingerprint_data, indent=2)
            
            if match_result:
                match_json = json.dumps(match_result, indent=2)
                prompt = f"""
                Analyze this IoT device fingerprint and profile matching result:
                
                Device Fingerprint:
                {fingerprint_json}
                
                Profile Matching Result:
                {match_json}
                
                Provide a comprehensive security analysis with:
                1. Device identification assessment (validity of reported manufacturer/model)
                2. Potential security concerns based on the fingerprint
                3. Unusual or suspicious characteristics
                4. Common vulnerabilities for this type of device
                5. Recommendations for securing this device
                
                Format your response as JSON with these fields:
                - identity_assessment: your assessment of the device's true identity
                - spoofing_risk: assessment of whether the device may be spoofing its identity (high/medium/low)
                - security_concerns: array of potential security issues based on the fingerprint
                - unusual_characteristics: array of unusual or suspicious aspects
                - common_vulnerabilities: array of vulnerabilities typically found in this type of device
                - security_recommendations: array of specific recommendations
                """
            else:
                prompt = f"""
                Analyze this IoT device fingerprint:
                
                Device Fingerprint:
                {fingerprint_json}
                
                Provide a comprehensive security analysis with:
                1. Device identification assessment (attempt to identify type of device)
                2. Potential security concerns based on the fingerprint
                3. Unusual or suspicious characteristics
                4. Recommendations for securing this device
                
                Format your response as JSON with these fields:
                - likely_device_type: your assessment of what type of device this might be
                - security_concerns: array of potential security issues based on the fingerprint
                - unusual_characteristics: array of unusual or suspicious aspects
                - security_recommendations: array of specific recommendations
                """
            
            response = openai.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are an IoT security expert specializing in device fingerprinting and security analysis."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.3
            )
            
            result = json.loads(response.choices[0].message.content)
            logger.info(f"AI analysis completed for device fingerprint {fingerprint.get('device_id')}")
            return result
            
        except Exception as e:
            logger.error(f"Error in AI analysis of device fingerprint: {str(e)}")
            return None
    
    def detect_counterfeit_device(self, fingerprint, match_result):
        """
        Detect potential counterfeit or unauthorized devices
        
        Args:
            fingerprint: Device fingerprint
            match_result: Profile matching result
            
        Returns:
            dict: Counterfeit detection results
        """
        try:
            # Initialize result
            result = {
                "counterfeit_likelihood": "low",
                "unauthorized_likelihood": "low",
                "suspicious_characteristics": [],
                "recommendation": "No action required"
            }
            
            # Check for manufacturer/model discrepancies
            reported_manufacturer = fingerprint.get("reported_manufacturer", "").lower()
            reported_model = fingerprint.get("reported_model", "").lower()
            
            if match_result and match_result.get("match_found"):
                identified_manufacturer = match_result.get("identified_manufacturer", "").lower()
                identified_model = match_result.get("identified_model", "").lower()
                
                # Check for identity mismatch
                if reported_manufacturer and identified_manufacturer and reported_manufacturer != identified_manufacturer:
                    result["counterfeit_likelihood"] = "high"
                    result["suspicious_characteristics"].append(
                        f"Device reports manufacturer as '{reported_manufacturer}' but behaves like '{identified_manufacturer}'"
                    )
                
                if reported_model and identified_model and reported_model != identified_model:
                    result["counterfeit_likelihood"] = "high"
                    result["suspicious_characteristics"].append(
                        f"Device reports model as '{reported_model}' but behaves like '{identified_model}'"
                    )
                
                # Set recommendation based on findings
                if result["counterfeit_likelihood"] == "high":
                    result["recommendation"] = "Isolate device and investigate. Likely counterfeit or compromised device."
            
            # Check for unauthorized devices (those not matching any approved profile)
            # This would typically compare against an approved inventory
            
            # Return detection results
            logger.info(f"Counterfeit detection for device {fingerprint.get('device_id')}: {result['counterfeit_likelihood']} likelihood")
            return result
            
        except Exception as e:
            logger.error(f"Error in counterfeit device detection: {str(e)}")
            return {
                "error": str(e),
                "counterfeit_likelihood": "unknown",
                "unauthorized_likelihood": "unknown"
            }


# Initialize fingerprinter
device_fingerprinter = DeviceFingerprinter()

def fingerprint_and_analyze_device(device, network_data=None):
    """
    Fingerprint and analyze a device for identification and security
    
    Args:
        device: Device object
        network_data: Optional network data for enhanced fingerprinting
        
    Returns:
        dict: Analysis results
    """
    try:
        # Generate device fingerprint
        fingerprint = device_fingerprinter.fingerprint_device(device, network_data)
        
        # Match against known profiles
        match_result = device_fingerprinter.match_device_profile(fingerprint)
        
        # Check for counterfeit/unauthorized devices
        counterfeit_result = device_fingerprinter.detect_counterfeit_device(fingerprint, match_result)
        
        # Perform AI analysis
        ai_analysis = device_fingerprinter.analyze_with_ai(fingerprint, match_result)
        
        # Compile results
        results = {
            "device_id": device.id,
            "fingerprint": fingerprint,
            "profile_match": match_result,
            "counterfeit_check": counterfeit_result
        }
        
        if ai_analysis:
            results["ai_analysis"] = ai_analysis
        
        logger.info(f"Device fingerprinting and analysis completed for device {device.id}")
        return results
        
    except Exception as e:
        logger.error(f"Error in device fingerprinting and analysis: {str(e)}")
        return {
            "device_id": device.id,
            "error": str(e)
        }