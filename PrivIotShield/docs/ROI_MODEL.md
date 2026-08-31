# PRIVIOT SHIELD — CUSTOMER OPERATIONAL RETURN ON INVESTMENT (ROI) MODEL
**Document Version:** 1.0.0-COMMERCIAL  
**Methodology:** Evidence-Based Operational Efficiency Model  
**Note:** All dollar figures and labor rates must be supplied by the customer organization.  

---

## 1. Operational Time & Cost Savings Dimensions

PrivIoT Shield generates quantifiable operational return across four primary workflows:

```
┌────────────────────────┐     ┌────────────────────────┐     ┌────────────────────────┐     ┌────────────────────────┐
│ 1. Asset Discovery     │     │ 2. Alert Triage &      │     │ 3. Containment &       │     │ 4. Compliance & Audit  │
│    Automation Savings  │  +  │    Forensic Analysis   │  +  │    Remediation Hours   │  +  │    Reporting Effort    │
└────────────────────────┘     └────────────────────────┘     └────────────────────────┘     └────────────────────────┘
```

---

## 2. Mathematical ROI Formulas

### Formula 1: Manual Asset Inventory & Device Auditing Savings
$$\text{Annual Hours Saved} = N_{\text{assets}} \times \left( T_{\text{manual\_inventory}} - T_{\text{priviot\_auto}} \right) \times F_{\text{audit\_frequency}}$$
* $N_{\text{assets}}$: Total connected IoT/OT endpoints across all plant facilities.
* $T_{\text{manual\_inventory}}$: Typical hours spent per device on manual switch-port tracing, MAC lookups, and spreadsheet updates (Industry benchmark: $0.5\text{ to }1.0\text{ hours/asset}$).
* $T_{\text{priviot\_auto}}$: PrivIoT automated discovery time ($0.0\text{ hours/asset}$).
* $F_{\text{audit\_frequency}}$: Audits per year (e.g., quarterly = 4).

### Formula 2: Alert Triage & Root-Cause Investigation Savings
$$\text{Annual Triage Savings (\$)} = N_{\text{alerts}} \times (\text{MTTI}_{\text{manual}} - \text{MTTI}_{\text{priviot}}) \times R_{\text{analyst\_hourly}}$$
* $N_{\text{alerts}}$: Total security alerts received annually.
* $\text{MTTI}_{\text{manual}}$: Average time required to manually investigate an unclassified IoT alert across multiple firewall/DNS logs (Industry benchmark: $45\text{ to }60\text{ minutes}$).
* $\text{MTTI}_{\text{priviot}}$: PrivIoT 3-column forensic chain investigation time ($< 1\text{ minute}$).
* $R_{\text{analyst\_hourly}}$: Fully burdened hourly cost of a SOC Security Analyst.

### Formula 3: Prevented Unscheduled OT Downtime
$$\text{Downtime Risk Reduction} = P_{\text{accidental\_block}} \times \text{Cost}_{\text{outage\_per\_hour}} \times T_{\text{recovery}}$$
* $P_{\text{accidental\_block}}$: Probability of an automated firewall rule severing operational traffic (reduced to $\approx 0\%$ via PrivIoT Safe Flow Preservation).
* $\text{Cost}_{\text{outage\_per\_hour}}$: Plant downtime financial impact per hour.

### Formula 4: Audit & Regulatory Reporting Acceleration
$$\text{Reporting Savings (\$)} = \left( H_{\text{manual\_compliance}} - H_{\text{priviot\_1click}} \right) \times R_{\text{compliance\_rate}}$$
* $H_{\text{manual\_compliance}}$: Hours spent compiling asset lists and CVE exposure reports for NIS2 / NIST CSF / HIPAA audits.
* $H_{\text{priviot\_1click}}$: PrivIoT on-demand executive report generation time ($< 0.1\text{ hours}$).
