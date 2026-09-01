import os
import sys
import json
import math
sys.path.insert(0, os.path.abspath("."))
from app import app
from models import Observation

sys.stdout.reconfigure(encoding='utf-8')
with app.app_context():
    obs = Observation.query.filter_by(collector_id=1).order_by(Observation.timestamp.asc()).all()
    bssid_data = {}
    for o in obs:
        p = json.loads(o.payload_json or '{}')
        bssid = (p.get('bssid') or p.get('raw_mac') or 'UNKNOWN').upper()
        ssid = p.get('ssid') or 'UNKNOWN'
        rssi = p.get('rssi')
        ch = p.get('channel')
        enc = p.get('encryption_type')
        if bssid not in bssid_data:
            bssid_data[bssid] = {'asset_id': o.asset_id, 'ssids': set(), 'rssis': [], 'channels': set(), 'enc': set(), 'count': 0}
        bssid_data[bssid]['count'] += 1
        bssid_data[bssid]['ssids'].add(str(ssid))
        if rssi is not None and isinstance(rssi, (int, float)):
            bssid_data[bssid]['rssis'].append(int(rssi))
        if ch is not None:
            bssid_data[bssid]['channels'].add(ch)
        if enc is not None:
            bssid_data[bssid]['enc'].add(enc)
            
    print(f"TOTAL UNIQUE BSSIDs: {len(bssid_data)}")
    for bssid, d in sorted(bssid_data.items(), key=lambda x: x[1]['count'], reverse=True):
        rssis = d['rssis']
        r_min = min(rssis) if rssis else 'N/A'
        r_max = max(rssis) if rssis else 'N/A'
        r_mean = sum(rssis)/len(rssis) if rssis else 'N/A'
        r_std = math.sqrt(sum((x - r_mean) ** 2 for x in rssis) / (len(rssis) - 1)) if len(rssis) > 1 else 0.0
        m_str = f"{r_mean:.1f}" if isinstance(r_mean, float) else "N/A"
        s_str = f"{r_std:.1f}"
        aid = d['asset_id']
        cnt = d['count']
        ssids = list(d['ssids'])
        chs = list(d['channels'])
        encs = list(d['enc'])
        print(f"{bssid} | Asset #{aid} | Count: {cnt} | SSIDs: {ssids} | Ch: {chs} | Enc: {encs} | RSSI: {r_min} to {r_max} (mean={m_str}, std={s_str})")
