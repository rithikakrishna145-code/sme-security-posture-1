"""
data_generator.py

Generates realistic synthetic data for simulated SME organizations.
"""

import random
import json
from datetime import datetime, timedelta

random.seed(42)

COMMON_PORTS = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443]
UNENCRYPTED_SERVICES_POOL = ["ftp", "telnet", "http-admin"]
EMPLOYEES = [f"user{i:03d}" for i in range(1, 21)]
NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 30)]
SUSPICIOUS_IPS = ["45.33.12.201", "103.22.44.9", "185.220.101.7"]


def generate_scan_result(risk_level="medium"):
    if risk_level == "low":
        return {"open_ports": random.sample(COMMON_PORTS, k=random.randint(2, 3)),
                "unencrypted_services": [], "firewall_active": True, "default_banners_detected": False}
    elif risk_level == "high":
        return {"open_ports": random.sample(COMMON_PORTS, k=random.randint(6, 9)),
                "unencrypted_services": random.sample(UNENCRYPTED_SERVICES_POOL, k=random.randint(1, 2)),
                "firewall_active": False, "default_banners_detected": True}
    else:
        return {"open_ports": random.sample(COMMON_PORTS, k=random.randint(4, 5)),
                "unencrypted_services": random.sample(UNENCRYPTED_SERVICES_POOL, k=random.randint(0, 1)),
                "firewall_active": True, "default_banners_detected": random.choice([True, False])}


def generate_vuln_data(risk_level="medium"):
    if risk_level == "low":
        return {"critical_cves": 0, "high_cves": 0, "eol_software_detected": False}
    elif risk_level == "high":
        return {"critical_cves": random.randint(1, 3), "high_cves": random.randint(2, 5), "eol_software_detected": True}
    else:
        return {"critical_cves": 0, "high_cves": random.randint(0, 2), "eol_software_detected": random.choice([True, False])}


def generate_endpoint_data(risk_level="medium"):
    if risk_level == "low":
        return {"exposed_sensitive_files": False, "backup_evidence_present": True, "logging_enabled": True}
    elif risk_level == "high":
        return {"exposed_sensitive_files": True, "backup_evidence_present": False, "logging_enabled": False}
    else:
        return {"exposed_sensitive_files": random.choice([True, False]),
                "backup_evidence_present": random.choice([True, False]), "logging_enabled": True}


def generate_login_logs(num_days=14, anomaly_rate=0.05):
    logs = []
    start = datetime.now() - timedelta(days=num_days)
    for day in range(num_days):
        date = start + timedelta(days=day)
        for _ in range(random.randint(15, 30)):
            ts = date.replace(hour=random.randint(8, 18), minute=random.randint(0, 59))
            logs.append({"timestamp": ts.isoformat(), "user": random.choice(EMPLOYEES),
                         "ip": random.choice(NORMAL_IPS), "success": True, "is_anomaly_ground_truth": False})
        if random.random() < anomaly_rate * 5:
            ts = date.replace(hour=random.choice([1, 2, 3, 4]), minute=random.randint(0, 59))
            logs.append({"timestamp": ts.isoformat(), "user": random.choice(EMPLOYEES),
                         "ip": random.choice(SUSPICIOUS_IPS), "success": random.choice([True, False]),
                         "is_anomaly_ground_truth": True})
    logs.sort(key=lambda x: x["timestamp"])
    return logs


def generate_org_profile(org_name, risk_level="medium"):
    logs = generate_login_logs()
    failed_last_24h = sum(1 for l in logs[-40:] if not l["success"])
    return {
        "org_name": org_name, "risk_level": risk_level,
        "scan_result": generate_scan_result(risk_level),
        "vuln_data": generate_vuln_data(risk_level),
        "endpoint_data": generate_endpoint_data(risk_level),
        "access_data": {"weak_credentials_detected": risk_level == "high",
                        "failed_logins_last_24h": failed_last_24h, "failed_login_threshold": 10},
        "login_logs": logs,
    }


if __name__ == "__main__":
    orgs = [
        generate_org_profile("SecureStitch Apparel Pvt Ltd", risk_level="low"),
        generate_org_profile("QuickBooks Retail Co", risk_level="medium"),
        generate_org_profile("LegacyWare Traders", risk_level="high"),
    ]
    with open("data/raw/synthetic_orgs.json", "w") as f:
        json.dump(orgs, f, indent=2)
    for org in orgs:
        print(f"{org['org_name']} ({org['risk_level']} risk): {len(org['login_logs'])} events, "
              f"{sum(1 for l in org['login_logs'] if l['is_anomaly_ground_truth'])} true anomalies")
    print("\nSaved to data/raw/synthetic_orgs.json")
