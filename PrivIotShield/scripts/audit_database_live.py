import os
import sys
import json
import math
sys.path.insert(0, os.path.abspath("."))
from app import app
from extensions import db
from models import Collector, Asset, Observation, BehavioralBaseline, BehavioralDriftEvent, Alert, RiskAssessment

sys.stdout.reconfigure(encoding='utf-8')

with app.app_context():
    collectors = Collector.query.all()
    print("=== COLLECTORS ===")
    for c in collectors:
        print(f"ID: {c.id} | UUID: {c.collector_uuid} | Name: {c.name} | Type: {c.collector_type} | Status: {c.status} | Last Heartbeat: {c.last_heartbeat} | Created At: {c.created_at}")
        
    esp32_c = Collector.query.filter_by(name='ESP32_Hardware_Scanner').first()
    c_id = esp32_c.id if esp32_c else None
    
    obs_query = Observation.query
    if c_id:
        obs_esp32 = obs_query.filter_by(collector_id=c_id).order_by(Observation.timestamp.asc()).all()
    else:
        obs_esp32 = obs_query.order_by(Observation.timestamp.asc()).all()
        
    print(f"\n=== OBSERVATIONS (Collector={c_id}) ===")
    print(f"Total observations: {len(obs_esp32)}")
    if obs_esp32:
        print(f"Earliest: {obs_esp32[0].timestamp}")
        print(f"Latest: {obs_esp32[-1].timestamp}")
        duration = obs_esp32[-1].timestamp - obs_esp32[0].timestamp
        print(f"Observation Window: {duration} ({duration.total_seconds() / 60:.1f} minutes)")
        
    # Analyze by BSSID
    bssid_data = {}
    for o in obs_esp32:
        p = json.loads(o.payload_json or '{}')
        bssid = (p.get('bssid') or p.get('raw_mac') or 'UNKNOWN').upper()
        ssid = p.get('ssid') or 'UNKNOWN'
        rssi = p.get('rssi')
        ch = p.get('channel')
        enc = p.get('encryption_type')
        
        if bssid not in bssid_data:
            bssid_data[bssid] = {
                'asset_id': o.asset_id,
                'ssids': set(),
                'rssis': [],
                'channels': set(),
                'encryptions': set(),
                'count': 0,
                'first_seen': o.timestamp,
                'last_seen': o.timestamp
            }
        bssid_data[bssid]['count'] += 1
        bssid_data[bssid]['ssids'].add(str(ssid))
        bssid_data[bssid]['last_seen'] = o.timestamp
        if rssi is not None and isinstance(rssi, (int, float)):
            bssid_data[bssid]['rssis'].append(int(rssi))
        if ch is not None:
            bssid_data[bssid]['channels'].add(ch)
        if enc is not None:
            bssid_data[bssid]['encryptions'].add(enc)
            
    print(f"\n=== BSSID STATISTICAL SUMMARY ({len(bssid_data)} unique BSSIDs) ===")
    for bssid, d in sorted(bssid_data.items(), key=lambda x: x[1]['count'], reverse=True):
        rssis = d['rssis']
        r_min = min(rssis) if rssis else "N/A"
        r_max = max(rssis) if rssis else "N/A"
        r_mean = sum(rssis)/len(rssis) if rssis else "N/A"
        if len(rssis) > 1:
            variance = sum((x - r_mean) ** 2 for x in rssis) / (len(rssis) - 1)
            r_std = math.sqrt(variance)
        else:
            r_std = 0.0
            
        mean_str = f"{r_mean:.1f}" if isinstance(r_mean, float) else "N/A"
        std_str = f"{r_std:.1f}" if isinstance(r_std, float) else "N/A"
        
        print(f"BSSID: {bssid} | Asset #{d['asset_id']} | Count: {d['count']} | SSIDs: {list(d['ssids'])} | Channels: {list(d['channels'])} | Enc: {list(d['encryptions'])} | RSSI (min/max/mean/std): {r_min}/{r_max}/{mean_str}/{std_str}")

    print("\n=== ASSETS ===")
    assets = Asset.query.all()
    print(f"Total Assets: {len(assets)}")
    for a in assets:
        print(f"Asset #{a.id} | MAC: {a.mac_address} | Hostname/SSID: {a.hostname} | Vendor: {a.vendor} | First: {a.first_seen} | Last: {a.last_seen}")

    print("\n=== BEHAVIORAL BASELINES ===")
    baselines = BehavioralBaseline.query.all()
    print(f"Total Baselines: {len(baselines)}")
    for b in baselines:
        s = json.loads(b.summary_json or '{}')
        print(f"Baseline #{b.id} | Asset #{b.asset_id} | Status: {b.status} | Stage: {s.get('maturity_stage')} | Conf: {s.get('maturity_confidence')} | Obs: {s.get('observation_count')} | RSSI Mean: {s.get('rssi_mean')} | Ch: {s.get('primary_channel')}")

    print("\n=== BEHAVIORAL DRIFT EVENTS ===")
    drifts = BehavioralDriftEvent.query.all()
    print(f"Total Drifts: {len(drifts)}")
    for d in drifts:
        print(f"Drift #{d.id} | Asset #{d.asset_id} | Type: {d.drift_type} | Severity: {d.severity} | Diff: {d.difference_description} | Created: {d.created_at}")

    print("\n=== RISK ASSESSMENTS ===")
    risks = RiskAssessment.query.all()
    print(f"Total Risk Assessments: {len(risks)}")
    for r in risks:
        print(f"Risk #{r.id} | Asset #{r.asset_id} | Score: {r.pri_score} | Level: {r.pri_level} | Threat Base: {r.threat_base} | Assessed At: {r.assessed_at}")

    print("\n=== ALERTS ===")
    alerts = Alert.query.all()
    print(f"Total Alerts: {len(alerts)}")
    for al in alerts:
        print(f"Alert #{al.id} | Asset #{al.asset_id} | Type: {al.alert_type} | Severity: {al.severity} | Title: {al.title} | Status: {al.status} | Created: {al.created_at}")
