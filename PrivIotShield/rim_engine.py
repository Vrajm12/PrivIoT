"""
PRIVIOT RIM — Radio Intelligence & Movement Engine
Single-Node 2.4 GHz Passive Radio Environment & Movement Trajectory System.
Transforms continuous 802.11 Wi-Fi scan observations into:
  - 20-Dimensional Dynamic Radio Fingerprint
  - Statistical RSSI Distribution (Mean, EMA, Variance, Noise Floor)
  - Multi-Sample Trajectory Estimator (Least-Squares Slope, Directional Consistency Index)
  - Relative Proximity Scoring (0–100, Very Far to Very Near)
  - Movement State Inference (Stationary, Approaching, Departing, Unstable, Unknown)
  - AP Presence & Recurrence Classifier (Present, Probably Present, Missing, Reappeared)
  - Multi-Feature Fingerprint Similarity Metric (0.0 to 1.0)
  - Cyber-Physical Security Classification (NORMAL, CHANGE, ANOMALY, THREAT)
"""

import json
import math
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger("priviot.engines.rim")


class RadioIntelligenceEngine:
    """
    Core mathematical engine for single-sensor radio environment intelligence.
    Enforces strict physical constraints: relative proximity only, no fake GPS coordinates.
    """

    SCAN_INTERVAL_SECONDS = 20.0  # Hardware ESP32 scan cycle time
    NOISE_FLOOR_STD_DEV = 3.5     # Minimum realistic RF standard deviation in indoor multipath (dB)
    RECEIVER_MIN_RSSI = -100.0    # ESP32 sensitivity threshold (dBm)
    RECEIVER_MAX_RSSI = -20.0     # ESP32 LNA saturation threshold (dBm)

    def calculate_statistical_rssi(self, history: List[int], current_rssi: Optional[int], 
                                  prev_ema: Optional[float] = None, alpha: float = 0.3) -> Dict[str, Any]:
        """
        Computes robust rolling statistical moments and Exponential Moving Average (EMA).
        """
        if not history and current_rssi is not None:
            history = [current_rssi]
        elif not history:
            history = [-60]

        n = len(history)
        mean_val = sum(history) / n
        min_val = min(history)
        max_val = max(history)

        if n > 1:
            variance = sum((x - mean_val) ** 2 for x in history) / (n - 1)
            std_dev = max(self.NOISE_FLOOR_STD_DEV, math.sqrt(variance))
        else:
            std_dev = self.NOISE_FLOOR_STD_DEV

        # Exponential Moving Average calculation
        if current_rssi is not None:
            if prev_ema is not None:
                ema_val = round(alpha * current_rssi + (1.0 - alpha) * prev_ema, 2)
            else:
                ema_val = round(float(current_rssi), 2)
        else:
            ema_val = round(prev_ema if prev_ema is not None else mean_val, 2)

        return {
            "sample_count": n,
            "mean": round(mean_val, 1),
            "std_dev": round(std_dev, 2),
            "min": min_val,
            "max": max_val,
            "ema": ema_val
        }

    def estimate_rssi_trend_and_movement(self, points: List[Dict[str, Any]], 
                                         mean_rssi: float, 
                                         std_dev: float) -> Dict[str, Any]:
        """
        Multi-Observation Trajectory Estimator.
        Uses Ordinary Least Squares (OLS) slope and Directional Consistency Index (DCI)
        across a window of consecutive observations to infer genuine physical movement
        versus indoor multipath RF noise.
        """
        if not points or len(points) < 3:
            return {
                "trend": "INSUFFICIENT_EVIDENCE",
                "movement_state": "UNKNOWN",
                "slope_db_per_sec": 0.0,
                "directional_consistency": 0.0,
                "window_points": len(points),
                "confidence": 0.20,
                "description": "Insufficient consecutive observations for movement trajectory estimation."
            }

        # Extract timestamps and RSSI values (use last K <= 10 points)
        recent = points[-10:]
        k = len(recent)

        # Parse relative timestamps in seconds from start of window
        t0 = recent[0].get("timestamp")
        if isinstance(t0, str):
            t0 = datetime.fromisoformat(t0.replace("Z", "+00:00"))

        t_secs = []
        rssi_vals = []
        for p in recent:
            ts = p.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            dt = (ts - t0).total_seconds() if (ts and t0) else 0.0
            t_secs.append(dt)
            rssi_vals.append(float(p.get("rssi", -60)))

        # 1. Linear Regression Slope: beta = Cov(t, RSSI) / Var(t)
        mean_t = sum(t_secs) / k
        mean_r = sum(rssi_vals) / k

        denom = sum((t - mean_t) ** 2 for t in t_secs)
        if denom > 1e-4:
            slope = sum((t_secs[i] - mean_t) * (rssi_vals[i] - mean_r) for i in range(k)) / denom
        else:
            # Fallback if timestamps are identical
            slope = (rssi_vals[-1] - rssi_vals[0]) / max(1.0, (k - 1) * self.SCAN_INTERVAL_SECONDS)

        # 2. Directional Consistency Index (DCI in [-1.0, +1.0])
        steps = []
        for i in range(1, k):
            diff = rssi_vals[i] - rssi_vals[i - 1]
            if diff > 1.0:
                steps.append(1.0)
            elif diff < -1.0:
                steps.append(-1.0)
            else:
                steps.append(0.0)
        dci = sum(steps) / (k - 1) if (k > 1) else 0.0

        # 3. Window Variance
        win_var = sum((r - mean_r) ** 2 for r in rssi_vals) / (k - 1) if (k > 1) else 0.0
        win_std = math.sqrt(win_var)

        # 4. Trajectory & Movement Classification
        # Net change across the window
        net_delta = rssi_vals[-1] - rssi_vals[0]
        recent_ema = recent[-1].get("ema", mean_r)

        # Minimum required evidence threshold
        if k < 5:
            trend = "INSUFFICIENT_EVIDENCE"
            movement = "UNKNOWN"
            confidence = 0.35
            desc = f"Preliminary signal window ({k} scans). Awaiting further samples."
        elif win_std > 12.0 and abs(dci) < 0.30:
            trend = "UNSTABLE"
            movement = "UNSTABLE"
            confidence = 0.50
            desc = f"Erratic signal oscillation (std={win_std:.1f} dB). Radio multipath or high interference."
        elif slope >= 0.12 and dci >= 0.40 and net_delta >= 6.0:
            trend = "APPROACHING"
            movement = "APPROACHING"
            confidence = min(0.95, 0.60 + (k / 10.0) * 0.25 + abs(dci) * 0.10)
            desc = f"Signal progressively strengthening (+{slope:.2f} dB/s, DCI=+{dci:.2f}). Proximity increasing toward sensor."
        elif slope <= -0.12 and dci <= -0.40 and net_delta <= -6.0:
            trend = "DEPARTING"
            movement = "DEPARTING"
            confidence = min(0.95, 0.60 + (k / 10.0) * 0.25 + abs(dci) * 0.10)
            desc = f"Signal progressively weakening ({slope:.2f} dB/s, DCI={dci:.2f}). Proximity receding from sensor."
        else:
            trend = "STABLE"
            movement = "STATIONARY"
            confidence = min(0.98, 0.70 + min(0.25, (k / 10.0) * 0.20))
            desc = f"Stable signal distribution (mean={mean_r:.1f} dBm, std={win_std:.1f} dB). Stationary relative proximity."

        return {
            "trend": trend,
            "movement_state": movement,
            "slope_db_per_sec": round(slope, 3),
            "directional_consistency": round(dci, 2),
            "window_points": k,
            "window_std_dev": round(win_std, 2),
            "net_rssi_delta": round(net_delta, 1),
            "confidence": round(confidence, 2),
            "description": desc
        }

    def calculate_relative_proximity(self, rssi_ema: float) -> Dict[str, Any]:
        """
        Calculates calibrated relative proximity score (0–100) across ESP32 dynamic range.
        -100 dBm (Sensitivity) -> 0 Score (VERY_FAR)
        -20 dBm  (Saturation)  -> 100 Score (VERY_NEAR)
        """
        clamped_rssi = max(self.RECEIVER_MIN_RSSI, min(self.RECEIVER_MAX_RSSI, rssi_ema))
        score = ((clamped_rssi - self.RECEIVER_MIN_RSSI) / (self.RECEIVER_MAX_RSSI - self.RECEIVER_MIN_RSSI)) * 100.0
        score_int = int(round(score))

        if score_int >= 80:
            state = "VERY_NEAR"
            desc = "Immediate line-of-sight proximity (RSSI >= -36 dBm)."
        elif score_int >= 60:
            state = "NEAR"
            desc = "Local room proximity (RSSI -52 to -37 dBm)."
        elif score_int >= 40:
            state = "MODERATE"
            desc = "Adjacent space proximity / structural drywall penetration (RSSI -68 to -53 dBm)."
        elif score_int >= 20:
            state = "FAR"
            desc = "Outer perimeter / structural boundary proximity (RSSI -84 to -69 dBm)."
        else:
            state = "VERY_FAR"
            desc = "Distant border / edge of receiver sensitivity (RSSI < -84 dBm)."

        return {
            "proximity_score": score_int,
            "proximity_state": state,
            "rssi_ema": round(rssi_ema, 1),
            "interpretation": desc
        }

    def evaluate_presence_and_recurrence(self, first_seen: Optional[datetime], 
                                         last_seen: Optional[datetime], 
                                         observation_count: int, 
                                         now: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Temporal Recurrence & Availability Classifier.
        Distinguishes temporary radio contention loss from prolonged disappearance.
        """
        now = now or datetime.utcnow()
        if not first_seen or not last_seen or observation_count <= 0:
            return {
                "presence_state": "UNKNOWN",
                "presence_ratio": 0.0,
                "missed_scans": 0,
                "elapsed_since_last_seen_sec": 0,
                "description": "No historical presence telemetry available."
            }

        elapsed_since_last_sec = max(0.0, (now - last_seen).total_seconds())
        total_lifespan_sec = max(1.0, (now - first_seen).total_seconds())

        expected_total_scans = max(1, int(total_lifespan_sec / self.SCAN_INTERVAL_SECONDS))
        presence_ratio = min(1.0, round(observation_count / float(expected_total_scans), 2))
        missed_scans = int(elapsed_since_last_sec / self.SCAN_INTERVAL_SECONDS)

        if missed_scans <= 2:  # <= 45s
            state = "PRESENT"
            desc = f"Active radio presence (seen {int(elapsed_since_last_sec)}s ago)."
        elif missed_scans <= 8:  # 46s - 3m
            state = "PROBABLY_PRESENT"
            desc = f"Brief scan absence ({missed_scans} missed cycles). Likely normal 802.11 channel contention."
        else:  # > 3m
            state = "MISSING"
            desc = f"Access point inactive / out of range ({missed_scans} missed scan cycles, elapsed {int(elapsed_since_last_sec/60)} mins)."

        return {
            "presence_state": state,
            "presence_ratio": presence_ratio,
            "missed_scans": missed_scans,
            "elapsed_since_last_seen_sec": int(elapsed_since_last_sec),
            "total_lifespan_sec": int(total_lifespan_sec),
            "description": desc
        }

    def calculate_fingerprint_similarity(self, current_obs: Dict[str, Any], 
                                         baseline_summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Multi-Dimensional Radio Fingerprint Similarity Metric ($S \in [0.0, 1.0]$).
        Quantifies whether the observed radio transmission conforms to the established baseline profile.
        Dimensions: Channel (25%), RSSI Profile (35%), Encryption Suite (20%), Identity (20%).
        """
        curr_ch = current_obs.get("channel")
        curr_rssi = current_obs.get("rssi")
        curr_enc = current_obs.get("encryption_type")
        curr_ssid = current_obs.get("ssid")

        base_ch = baseline_summary.get("primary_channel")
        base_mean = baseline_summary.get("rssi_mean", -60.0)
        base_std = max(self.NOISE_FLOOR_STD_DEV, baseline_summary.get("rssi_std_dev", 4.0))
        base_enc = baseline_summary.get("encryption_type")
        base_ssid = baseline_summary.get("primary_ssid")

        # 1. Channel Match
        if base_ch is not None and curr_ch is not None:
            s_channel = 1.0 if curr_ch == base_ch else 0.30
        else:
            s_channel = 0.80

        # 2. RSSI Gaussian Kernel Similarity
        if curr_rssi is not None:
            delta_rssi = abs(curr_rssi - base_mean)
            s_rssi = math.exp(- (delta_rssi ** 2) / (2.0 * (base_std ** 2)))
        else:
            s_rssi = 0.80

        # 3. Encryption Suite Match
        if base_enc is not None and curr_enc is not None:
            s_enc = 1.0 if curr_enc == base_enc else 0.0
        else:
            s_enc = 0.90

        # 4. SSID Identity Match
        if base_ssid and curr_ssid and base_ssid != "Unknown":
            s_ssid = 1.0 if curr_ssid == base_ssid else 0.0
        else:
            s_ssid = 0.85

        # Weighted composite score
        total_sim = 0.25 * s_channel + 0.35 * s_rssi + 0.20 * s_enc + 0.20 * s_ssid
        total_sim = round(max(0.0, min(1.0, total_sim)), 3)

        if total_sim >= 0.85:
            verdict = "MATCH"
            verdict_desc = "Radio emissions strictly match established device baseline."
        elif total_sim >= 0.60:
            verdict = "PARTIAL_DRIFT"
            verdict_desc = "Moderate radio divergence observed (channel hop, signal delta, or proximity shift)."
        else:
            verdict = "ANOMALOUS"
            verdict_desc = "Significant radio fingerprint discrepancy (identity mismatch or security downgrade)."

        return {
            "similarity_score": total_sim,
            "similarity_percent": round(total_sim * 100.0, 1),
            "verdict": verdict,
            "components": {
                "channel_similarity": round(s_channel, 2),
                "rssi_similarity": round(s_rssi, 2),
                "encryption_similarity": round(s_enc, 2),
                "ssid_similarity": round(s_ssid, 2)
            },
            "description": verdict_desc
        }

    def classify_cyber_physical_event(self, fingerprint: Dict[str, Any], 
                                      baseline_summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        4-Tier Cyber-Physical Taxonomy:
          - NORMAL: Normal RF fluctuation within statistical bounds.
          - CHANGE: Environmental movement (approaching/departing) or expected RF omission.
          - ANOMALY: Statistically abnormal channel switch or RF outlier.
          - THREAT: Security-relevant downgrade, identity spoof, or rogue AP duplicate.
        """
        movement = fingerprint.get("movement_state", "STATIONARY")
        sim_score = fingerprint.get("similarity_score", 1.0)
        curr_enc = fingerprint.get("encryption_type")
        prev_enc = baseline_summary.get("encryption_type")
        curr_ssid = fingerprint.get("ssid")
        base_ssid = baseline_summary.get("primary_ssid")
        obs_count = fingerprint.get("observation_count", 0)

        # 1. THREAT Check
        if curr_enc == 0 and prev_enc is not None and prev_enc > 0 and obs_count >= 5:
            return {
                "classification": "THREAT",
                "severity": "critical",
                "pri_impact": 2.0,
                "reason": "Airspace Threat: 802.11 cipher downgraded to Cleartext Unencrypted Open."
            }
        if curr_ssid and base_ssid and curr_ssid != base_ssid and base_ssid != "Unknown" and obs_count >= 10:
            return {
                "classification": "THREAT",
                "severity": "high",
                "pri_impact": 1.5,
                "reason": f"Identity Anomaly: BSSID broadcast SSID altered from '{base_ssid}' to '{curr_ssid}'."
            }

        # 2. ANOMALY Check
        if sim_score < 0.60 and obs_count >= 10:
            return {
                "classification": "ANOMALY",
                "severity": "medium",
                "pri_impact": 0.5,
                "reason": "Radio Anomaly: Significant multi-feature baseline divergence."
            }

        # 3. CHANGE Check
        if movement in ("APPROACHING", "DEPARTING"):
            return {
                "classification": "CHANGE",
                "severity": "info",
                "pri_impact": 0.0,
                "reason": f"Environmental Proximity Change: Device observed {movement.lower()} relative to sensor."
            }

        # 4. NORMAL
        return {
            "classification": "NORMAL",
            "severity": "none",
            "pri_impact": 0.0,
            "reason": "Radio transmission conforming to established normal baseline."
        }


# Singleton instance
rim_engine = RadioIntelligenceEngine()
