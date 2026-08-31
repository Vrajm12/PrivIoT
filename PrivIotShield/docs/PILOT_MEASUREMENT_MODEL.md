# PRIVIOT SHIELD — PILOT MEASUREMENT & EVIDENCE MODEL
**Document Version:** 1.0.0-VALIDATION  
**Scope:** Pilot 01 Operational Metrics Engine  

---

## 1. Real Pilot Telemetry & Denominator Schema

Every metric rendered on `/pilot` adheres to a strict 3-field provenance schema:
1. **Source:** Originating sensor node, packet filter, or user action.
2. **Time Window:** Actual elapsed duration under real observation clock.
3. **Denominator:** Total eligible population (e.g. Total Assets, Labeled Assets, Operational Flows).

```
┌─────────────────────────────────────────────────────────────┐
│ METRIC: IDENTITY PRECISION                                  │
│ - Value: 100.0%                                             │
│ - Denominator: 4 Ground-Truth Verified Assets               │
│ - Source: Operator Ground-Truth Audit Log                   │
│ - Scope: 4 Correct / 0 False                                │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Quantitative Metric Formulations

### 1. Ground-Truth Coverage Rate
$$\text{Coverage} = \frac{N_{\text{ground\_truth\_labeled}}}{N_{\text{total\_discovered}}} = \frac{4}{5} = 80.0\%$$

### 2. Identity Precision Rate
$$\text{Precision} = \frac{\text{True Positives}}{\text{True Positives} + \text{False Positives}} = \frac{4}{4 + 0} = 100.0\%$$

### 3. Unknown Device Uncertainty Rate
$$\text{Uncertainty Rate} = \frac{N_{\text{unclassified\_iot}}}{N_{\text{total\_discovered}}} = \frac{1}{5} = 20.0\%$$

### 4. Behavioral Baseline Learning Maturity
$$\text{Maturity} = \frac{T_{\text{elapsed\_steady\_state}}}{T_{\text{required\_convergence}}} = \frac{T_{\text{actual}}}{48.0\text{ hours}} \quad (\text{Real Clock})$$
