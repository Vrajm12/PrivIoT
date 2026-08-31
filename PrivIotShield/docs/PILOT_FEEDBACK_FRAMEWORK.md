# PRIVIOT SHIELD — STRUCTURED PILOT FEEDBACK FRAMEWORK
**Customer Feedback Triage, Defect Classification, and Feature Governance**  
**Version:** 6.0.0-PILOT  

---

## 1. Feedback Classification Hierarchy

All operational feedback collected during customer pilot engagements is classified into four strict triage buckets:

```
┌──────────────────────────────────────────────────────────────┐
│ P0: CRITICAL SECURITY / DATA ISOLATION DEFECT                │
│ (Immediate engineering hotfix; blocks pilot continuation)   │
├──────────────────────────────────────────────────────────────┤
│ P1: PILOT BLOCKER / SENSOR CRASH / INGESTION FAILURE         │
│ (Resolved within 24 hours; prevents core loop evaluation)   │
├──────────────────────────────────────────────────────────────┤
│ P2: WORKFLOW FRICTION / FALSE POSITIVE TUNING                │
│ (Triaged for next scheduled minor release)                  │
├──────────────────────────────────────────────────────────────┤
│ P3: FEATURE REQUEST / NICE-TO-HAVE INTEGRATION               │
│ (Logged in customer backlog; evaluated post-pilot)          │
└──────────────────────────────────────────────────────────────┘
```

---

## 2. Customer Feedback Record Template

```markdown
### Feedback Entry: [PILOT-FB-XXX]
* **Customer / Site:** [e.g. Acme Health / Site 01]
* **Date Observed:** [YYYY-MM-DD]
* **Reported By:** [Operator Role / Name]
* **Severity Tier:** [P0 / P1 / P2 / P3]
* **Component Affected:** [Discovery | Identity | Baseline | PRI | Containment | UI]
* **Observation / Friction Point:** [Detailed description of what occurred]
* **Expected vs Actual Behavior:** [What was expected vs what happened]
* **Workaround Applied:** [If any]
* **Action Required:** [Bug Fix / Configuration Tuning / Documentation Update]
```
