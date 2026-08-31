# PRIVIOT SHIELD — FRONTEND MIGRATION MAP (FLASK -> NEXT.JS)
**Document Version:** 1.0.0-MIGRATION  
**Mapping Date:** August 31, 2026  
**Scope:** 1-to-1 Translation of Jinja2 Templates into Next.js 14+ TypeScript Pages & Components

---

## 1. Screen & Route Migration Matrix

| # | Current Flask Route | Current Jinja2 Template | Current Backend API | Target Next.js App Router Path | Target Component Structure | Required API Schema / Endpoints |
| :- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `GET /dashboard` | `dashboard.html` | Server-rendered model queries + `/api/v2/alerts`, `/api/v3/fleet/health` | `app/(dashboard)/page.tsx` | `DashboardView.tsx`, `KpiSummaryGrid.tsx`, `CriticalActionHero.tsx`, `LivePostureTable.tsx`, `SensorFleetHealth.tsx` | `GET /api/v1/dashboard/summary` (Aggregated KPIs, critical assets, active alerts, collector status in one JSON payload). |
| 2 | `GET /devices` | `devices.html` | Server-rendered `Asset.query` + `/api/v2/assets` | `app/(dashboard)/inventory/page.tsx` | `InventoryView.tsx`, `AssetDataTable.tsx`, `InventoryFilterChips.tsx`, `AssetQuickDrawer.tsx` | `GET /api/v1/assets` (Filterable by `status`, `severity`, `drift`, `needs_verification`, with pagination). |
| 3 | `GET /device/<id>`<br>`GET /assets/<id>/trust-profile` | `trust_profile.html`<br>`device_detail.html` | `/api/v2/assets/<id>/trust-profile`<br>`/api/v2/assets/<id>/behavior`<br>`/api/v2/assets/<id>/vulnerabilities` | `app/(dashboard)/inventory/[assetId]/page.tsx` | `TrustProfileView.tsx`, `IdentityClaimsCard.tsx`, `PriBreakdownCard.tsx`, `VulnCatalogTab.tsx`, `BehaviorBaselineTab.tsx`, `ContainmentRulesTab.tsx`, `AuditTimelineTab.tsx` | `GET /api/v1/assets/{assetId}/trust-profile` (Returns canonical 11-category JSON payload). |
| 4 | `GET /alerts`<br>`GET /alerts/<id>` | `alerts.html`<br>`alert_detail.html` | `/api/v2/alerts`<br>`/api/v2/alerts/<id>` | `app/(dashboard)/alerts/page.tsx`<br>`app/(dashboard)/alerts/[alertId]/page.tsx` | `AlertsListView.tsx`, `AlertIncidentCard.tsx`, `EvidenceTriageModal.tsx`, `ContainmentQuickAction.tsx` | `GET /api/v1/alerts` (List with status filter), `POST /api/v1/alerts/{id}/acknowledge`, `POST /api/v1/alerts/{id}/resolve`. |
| 5 | `GET /trends` | `trends.html` | `/api/trends/global`<br>`/api/trends/device/<id>` | `app/(dashboard)/behavior/page.tsx` | `BehaviorDriftView.tsx`, `TrafficVolumeChart.tsx`, `EgressFlowsMatrix.tsx`, `DgaAnomalyFeed.tsx` | `GET /api/v1/behavior/drift-feed`, `GET /api/v1/behavior/flows-matrix`. |
| 6 | `GET /remediation` | `remediation.html` | `/api/v2/remediation/firewall-rules`<br>`/api/v2/assets/<id>/containment/apply` | `app/(dashboard)/containment/page.tsx` | `ContainmentConsoleView.tsx`, `ActivePolicyCard.tsx`, `SafeFlowsPreservedBox.tsx`, `ProviderMaturityMatrix.tsx`, `RollbackConfirmModal.tsx` | `GET /api/v1/containment/policies`, `POST /api/v1/containment/preview`, `POST /api/v1/containment/approve`, `POST /api/v1/containment/apply`, `POST /api/v1/containment/rollback`. |
| 7 | `GET /reports`<br>`GET /report/<id>` | `reports.html`<br>`report_detail.html` | `/api/v3/reports/generate`<br>`/api/v3/reports/executive-summary` | `app/(dashboard)/reports/page.tsx` | `ReportsGridView.tsx`, `ReportCard.tsx`, `ReportPreviewModal.tsx`, `PdfDownloadButton.tsx` | `GET /api/v1/reports` (Live reports metadata), `POST /api/v1/reports/export` (PDF/CSV generation). |
| 8 | `GET /network-scan` | `network_scan.html` | `/api/network-scan/start`<br>`/api/device/import` | `app/(dashboard)/discovery/page.tsx` | `DiscoveryProbeView.tsx`, `SubnetScanForm.tsx`, `DiscoveredDeviceTable.tsx`, `ImportAssetDialog.tsx` | `POST /api/v1/discovery/scan`, `POST /api/v1/discovery/import`. |
| 9 | `GET /security-tips`<br>`GET /tips` | `security_tips.html` | `/api/v2/compliance/audit`<br>`/api/tips/personalized` | `app/(dashboard)/compliance/page.tsx` | `ComplianceAuditView.tsx`, `EtsiStandardCard.tsx`, `NistControlList.tsx`, `RemediationChecklist.tsx` | `GET /api/v1/compliance/etsi-en-303-645`, `GET /api/v1/compliance/nist-ir-8259`. |
| 10 | `GET /api_docs`<br>`GET /api-docs` | `api_docs.html` | Server-rendered current user API key | `app/(dashboard)/settings/api-tokens/page.tsx` | `ApiTokensView.tsx`, `CollectorTokenGenerator.tsx`, `TokenRotationTable.tsx` | `GET /api/v1/tokens`, `POST /api/v1/tokens/generate`, `POST /api/v1/tokens/{id}/rotate`. |
| 11 | `GET /profile` | `profile.html` | Server-rendered user details | `app/(dashboard)/settings/profile/page.tsx` | `UserProfileView.tsx`, `PasswordChangeForm.tsx`, `TenantInfoCard.tsx` | `GET /api/v1/auth/me`, `PUT /api/v1/auth/profile`. |
| 12 | `GET /login`<br>`GET /register` | `login.html`<br>`register.html` | `/login`, `/register` (form POST) | `app/(auth)/login/page.tsx`<br>`app/(auth)/register/page.tsx` | `LoginForm.tsx`, `RegisterForm.tsx`, `AuthLayout.tsx` | `POST /api/v1/auth/token` (OAuth2 / JWT login), `POST /api/v1/auth/register`. |

---

## 2. Reusable Component Hierarchy (Target TypeScript/React)

```
src/
├── app/
│   ├── (auth)/
│   │   ├── login/page.tsx
│   │   └── register/page.tsx
│   └── (dashboard)/
│       ├── layout.tsx                <- Persistent Left Sidebar + Top Context Bar + SSE Hook
│       ├── page.tsx                  <- Operational Security Console (/dashboard)
│       ├── inventory/
│       │   ├── page.tsx              <- Live Security Inventory (/devices)
│       │   └── [assetId]/page.tsx    <- Flagship Device Trust Profile (/device/<id>)
│       ├── alerts/
│       │   ├── page.tsx              <- Alerts Incident Feed
│       │   └── [alertId]/page.tsx    <- Incident Deep-Dive Triage
│       ├── behavior/page.tsx         <- 48h Baseline & Drift Analytics (/trends)
│       ├── containment/page.tsx      <- Micro-Segmentation & Quarantine Console
│       ├── reports/page.tsx          <- Compliance & Enterprise Reports
│       ├── discovery/page.tsx        <- Discovery Probes & Subnet Scanner
│       ├── compliance/page.tsx       <- ETSI EN 303 645 & NIST IR 8259 Audit
│       └── settings/
│           ├── profile/page.tsx
│           ├── api-tokens/page.tsx
│           └── collectors/page.tsx   <- Edge Collector Fleet Management
├── components/
│   ├── ui/                           <- Radix / Tailwind Primitive Atoms (Button, Badge, Table, Modal)
│   ├── layout/                       <- Sidebar, TopContextBar, OperatorProfileDropdown
│   ├── trust-profile/                <- 7 Progressive Disclosure Tabs
│   ├── containment/                  <- Multi-Provider Rule Cards & Rollback Triggers
│   └── realtime/                     <- SSE Event Listener & Toast Notifications
└── lib/
    ├── api-client.ts                 <- Typed fetch/Axios client with automatic token refresh
    ├── sse-client.ts                 <- Server-Sent Events stream manager
    └── tokens.ts                     <- Dark SOC Design System color and style tokens
```

---

## 3. Real-Time Telemetry Streaming Architecture

In the target Next.js architecture, the `RealtimeProvider` wraps the dashboard layout:
1. Opens an `EventSource` connection to `/api/v1/events/stream`.
2. Listens for server-published event types:
   * `ASSET_DISCOVERED`: Prepends new asset to `AssetDataTable` and increments top KPI badge.
   * `DRIFT_DETECTED`: Displays high-priority warning toast and updates affected asset's PRI badge.
   * `CONTAINMENT_UPDATED`: Changes firewall rule state tag from `◐ APPLYING` to `● VERIFIED`.
   * `COLLECTOR_HEARTBEAT`: Refreshes fleet health indicators without polling.
3. Automatically falls back to TanStack Query interval polling (30s) if SSE is severed.
