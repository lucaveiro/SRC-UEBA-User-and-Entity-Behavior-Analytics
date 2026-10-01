# TODO — UEBA Module for SIEM

> Track progress for the Security in Communications Networks — Project 2

---

## Setup

- [x] Determine dataset index `X = (num_mec1 + num_mec2) % 10` → **X = 3** (using `dataset3/`)
- [x] Download dataset `dataset3.zip` from Moodle and extract into `dataset3/`
- [x] Download DB-IP geolocation databases and place in project root
  - [x] `dbip-country-lite-2026-05.mmdb`
  - [x] `dbip-asn-lite-2026-05.mmdb`
- [x] Install Python dependencies (`pandas`, `numpy`, `matplotlib`, `seaborn`, `geoip2`, `jupyter`)
- [x] Read through `sampleScript.py` to understand provided helpers

---

## Notebook 01 — Baseline Analysis (Training Data)

- [x] Load `internal_train3.json` and `external_train3.json`
- [x] Identify the private IPv4 network(s) in use → **192.168.103.0/24** (public corporate: **200.0.0.0/24**)
- [x] Identify internal servers and services (by IP + port)
- [x] Compute per-IP upload/download statistics and ratios (internal users)
- [x] Compute destination country distribution (internal users → external servers)
- [x] Compute flow interval statistics for external users accessing corporate servers (`200.0.0.0/24`)
- [x] Compute overall traffic ratios for external users (flows, bytes, ports)
- [x] Save baseline profiles (means, std devs, thresholds) — embedded directly in detection cells

---

## Notebook 02 — Internal Anomaly Detection

### Rule i — Internal BotNet Activity (2 pts)
- [x] Define rule based on baseline (`cv_interval` + `n_dst_servers` fan-out)
- [x] Justify threshold with training data plots (scatter: fan-out vs regularidade temporal)
- [x] Apply to `internal_test3.json` (cell added to notebook)
- [x] Flagged: 192.168.103.110, 192.168.103.153, 192.168.103.207

### Rule ii — Data Exfiltration via HTTPS / DNS (4 pts)
- [x] Define HTTPS exfiltration rule (upload volume + upload/download ratio on port 443)
- [x] Define DNS exfiltration rule (DNS flow count + upload on port 53)
- [x] Justify thresholds with training data plots (upload vs download scatter)
- [x] Apply to `internal_test3.json` (cells added to notebook)
- [x] HTTPS flagged: 192.168.103.103, 192.168.103.153, 192.168.103.187, 192.168.103.32, 192.168.103.81
- [x] DNS flagged: 192.168.103.114, 192.168.103.118, 192.168.103.80, 192.168.103.92, 192.168.103.99

### Rule iii — C&C via DNS (2 pts)
- [x] Define rule based on DNS flow regularity / beaconing interval (`cv_interval_dns`)
- [x] Justify threshold with training data
- [x] Apply to `internal_test3.json` (cell added to notebook)
- [x] Flagged: 192.168.103.195

### Rule iv — Anomalous External Destinations (2 pts)
- [x] Define rule based on never-before-seen destination countries
- [x] Justify with training data country/ASN distribution (bar chart of destination countries)
- [x] Apply to `internal_test3.json` (cell added to notebook)
- [x] Flagged: 192.168.103.20, 192.168.103.21, 192.168.103.59

---

## Notebook 03 — External Anomaly Detection

### Rule v — Anomalous External Usage of Corporate Servers (2 pts)
- [x] Define rule based on inter-flow interval patterns (`cv_interval`) and upload/download ratio
- [x] Justify threshold with training data plots (cv_interval histogram for external clients)
- [x] Apply to `external_test3.json` (cell added to notebook)
- [x] Flagged: 188.83.74.162, 188.83.74.33, 188.83.74.51, 188.83.74.61, 188.83.74.64

---

## Notebook 04 — SIEM Reporting (1 pt, optional)

- [x] Configure `SIEM_HOST` and `SIEM_PORT` → 172.100.0.12:514
- [x] Implement rsyslog message sending (`Alarm UEBA <ip>`) for each flagged IP (21 alarms sent via `logger`)
- [x] Verify that Wazuh receives and parses alerts correctly (decoder `ueba_alarm` + rule 100201)

---

## Report

- [x] Section 1 — Non-anomalous behavior analysis
  - [x] Private network(s) identified
  - [x] Internal servers/services identified
  - [x] Internal user traffic statistics (upload/download, ratios, countries)
  - [x] External user traffic statistics (overall, ratios, flow intervals)
- [x] Section 2 — UEBA rule definitions and justifications (one per rule, with plots)
- [x] Section 3 — Rule test results with flagged IP addresses per rule (all IPs filled in, summary table complete)
- [x] Section 4 — SIEM reporting (decoder, rule, alarm sending, verification steps)
- [ ] Proofread and export to PDF
- [ ] Submit via e-learning **before June 8th (inclusive)**

---

## Submission Checklist

- [ ] All notebooks run cleanly top-to-bottom with no errors
- [x] All rule thresholds derived from training data (no hardcoded magic numbers)
- [ ] Report in PDF format
- [ ] Submitted by both group members on Moodle
