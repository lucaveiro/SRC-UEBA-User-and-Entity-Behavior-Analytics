# UEBA Module for SIEM — Network Anomaly Detection

**Security in Communications Networks (Segurança em Redes de Comunicações)**  
DETI — Universidade de Aveiro  
Second Project · 2026

---

## Overview

This project implements a **User and Entity Behavior Analytics (UEBA)** module for a SIEM system. The module analyzes IP traffic flow logs from a corporate network to establish behavioral baselines and detect anomalous network behaviors indicative of compromised devices.

Detection targets include internal botnet activity, data exfiltration over HTTPS/DNS, Command & Control (C&C) communication via DNS, anomalous external destinations, and abnormal usage of corporate public servers by external clients.


---

## Dataset Format

Each JSON file stores a Pandas DataFrame. Each row represents one IPv4 flow with the following fields:

| Column | Description |
|---|---|
| `timestamp` | Time of first packet (1/100 s from 00:00:00) |
| `src_ip` | Source IPv4 address (internal device or external client) |
| `dst_ip` | Destination IPv4 address |
| `proto` | Transport protocol (`tcp` or `udp`) |
| `port` | Destination port |
| `up_bytes` | Total bytes uploaded |
| `down_bytes` | Total bytes downloaded |

---

## Detection Rules

All rule thresholds are derived from the training data (baseline). No hardcoded values are used.

| # | Rule | Points |
|---|---|---|
| i | Internal BotNet activity detection | 2 |
| ii | Data exfiltration via HTTPS and/or DNS | 4 |
| iii | C&C activity detection via DNS | 2 |
| iv | Anomalous external destinations | 2 |
| v | Anomalous external usage of corporate public servers | 2 |

---

## Setup

### Requirements

- Python 3.8+
- pandas
- numpy
- ipaddress
- matplotlib / seaborn (for plots)
- dnspython (optional, for DNS queries)
- jupyter

Install dependencies:

```bash
pip install pandas numpy matplotlib seaborn dnspython jupyter
```

### Geolocation Databases

Download the free lite databases from [DB-IP](https://db-ip.com/db/download/ip-to-country-lite) and place them in the `dbip/` directory:

- `dbip-country-lite.csv`
- `dbip-asn-lite.csv`

These are also available on the course Moodle page.

---

## Notebooks

Launch Jupyter and run the notebooks in order:

```bash
jupyter notebook
```

| Notebook | Description |
|---|---|
| `01_baseline_analysis.ipynb` | Load training data, explore traffic patterns, compute per-IP behavioral baselines (upload/download stats, destination countries, port usage, flow intervals) |
| `02_internal_detection.ipynb` | Apply rules i–iv to `internal_testX.json` and flag anomalous internal devices |
| `03_external_detection.ipynb` | Apply rule v to `external_testX.json` and flag anomalous external clients |
| `04_siem_reporting.ipynb` | Send rsyslog alerts to a SIEM (Wazuh/ELK) for all flagged IPs |

Each notebook is self-contained with markdown cells explaining the methodology and inline plots for threshold justification.

---

## SIEM Reporting (Optional)

If a SIEM endpoint is configured, the script sends rsyslog messages for each detected anomaly:

```
Alarm UEBA <ip_address>
```

Configure the SIEM host and port at the top of `04_siem_reporting.ipynb`:

```python
SIEM_HOST = "172.100.0.12"
SIEM_PORT = 514
```

This integrates with a Wazuh custom decoder (`ueba_alarm`) and rule to generate level-7 security events per anomalous device detected.

---

## Important Notes

- All public IPv4 addresses in the dataset represent real networks. Only owner/location metadata is relevant — **do not perform service or vulnerability scans on any IP address.**
- Geolocation must rely exclusively on the DB-IP databases, not on live lookups.
- Each device's private IPv4 address is assumed stable for the full day (one IP = one end-user).

---

## Authors

| Name | Student Number |
|---|---|
| Ruben Lopes | 103009 |
| Lucas Rebelo | 123934 |

---

## Professors

Paulo Salvador · Victor Marques · Alfredo Matos  
DETI — Universidade de Aveiro