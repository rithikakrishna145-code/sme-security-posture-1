"""
scoring_engine.py

Implements the CIS-benchmark-grounded posture scoring logic. Every deduction
is traceable to a named finding, supporting the "lineage tracking" requirement
from the project brief.
"""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class Finding:
    category: str
    check_name: str
    passed: bool
    points_possible: float
    points_awarded: float
    detail: str


@dataclass
class ScoreReport:
    org_name: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def total_score(self) -> float:
        return round(sum(f.points_awarded for f in self.findings), 2)

    @property
    def max_score(self) -> float:
        return sum(f.points_possible for f in self.findings)

    @property
    def category_breakdown(self) -> Dict[str, Dict[str, float]]:
        breakdown = {}
        for f in self.findings:
            cat = breakdown.setdefault(f.category, {"awarded": 0.0, "possible": 0.0})
            cat["awarded"] += f.points_awarded
            cat["possible"] += f.points_possible
        return breakdown

    def rating(self) -> str:
        score = self.total_score
        if score >= 85:
            return "Strong"
        elif score >= 65:
            return "Moderate"
        elif score >= 40:
            return "Weak"
        else:
            return "Critical"

    def to_dict(self) -> dict:
        return {
            "org_name": self.org_name,
            "total_score": self.total_score,
            "max_score": self.max_score,
            "rating": self.rating(),
            "category_breakdown": self.category_breakdown,
            "findings": [f.__dict__ for f in self.findings],
        }


def score_network_security(scan_result: dict) -> List[Finding]:
    findings = []
    open_ports = scan_result.get("open_ports", [])
    non_standard_open = [p for p in open_ports if p not in (80, 443)]
    passed = len(non_standard_open) <= 3
    findings.append(Finding("Network Security", "Unnecessary open ports", passed, 8,
                             8 if passed else 0,
                             f"{len(non_standard_open)} non-standard open ports: {non_standard_open}"))

    unencrypted = scan_result.get("unencrypted_services", [])
    passed = len(unencrypted) == 0
    findings.append(Finding("Network Security", "No unencrypted services exposed", passed, 8,
                             8 if passed else 0,
                             f"Unencrypted services found: {unencrypted}" if unencrypted else "None found"))

    passed = scan_result.get("firewall_active", False)
    findings.append(Finding("Network Security", "Firewall active", passed, 5,
                             5 if passed else 0,
                             "Firewall active" if passed else "Firewall not detected/inactive"))

    passed = not scan_result.get("default_banners_detected", False)
    findings.append(Finding("Network Security", "No default service banners exposed", passed, 4,
                             4 if passed else 0,
                             "Clean" if passed else "Default/identifiable banners exposed"))
    return findings


def score_access_control(access_data: dict, anomaly_flag: bool) -> List[Finding]:
    findings = []
    passed = not access_data.get("weak_credentials_detected", False)
    findings.append(Finding("Access Control", "No default/weak credential patterns", passed, 10,
                             10 if passed else 0,
                             "Clean" if passed else "Weak/default credential pattern detected"))

    failed = access_data.get("failed_logins_last_24h", 0)
    threshold = access_data.get("failed_login_threshold", 10)
    passed = failed <= threshold
    findings.append(Finding("Access Control", "Failed logins within baseline threshold", passed, 5,
                             5 if passed else 0,
                             f"{failed} failed logins in 24h (threshold: {threshold})"))

    passed = not anomaly_flag
    findings.append(Finding("Access Control", "No anomalous login pattern (ML)", passed, 10,
                             10 if passed else 0,
                             "No anomaly detected by model" if passed else "Isolation Forest flagged anomalous access pattern"))
    return findings


def score_patch_management(vuln_data: dict) -> List[Finding]:
    findings = []
    critical = vuln_data.get("critical_cves", 0)
    passed = critical == 0
    findings.append(Finding("Patch & Vulnerability Management", "No critical CVEs (CVSS >= 9.0)", passed, 12,
                             12 if passed else 0, f"{critical} critical CVE(s) found"))

    high = vuln_data.get("high_cves", 0)
    passed = high == 0
    findings.append(Finding("Patch & Vulnerability Management", "No high-severity CVEs (CVSS 7.0-8.9)", passed, 8,
                             8 if passed else (8 * max(0, 1 - high / 5)), f"{high} high-severity CVE(s) found"))

    passed = not vuln_data.get("eol_software_detected", False)
    findings.append(Finding("Patch & Vulnerability Management", "No known end-of-life software", passed, 5,
                             5 if passed else 0, "Clean" if passed else "EOL software detected"))
    return findings


def score_endpoint_hygiene(endpoint_data: dict) -> List[Finding]:
    findings = []
    passed = not endpoint_data.get("exposed_sensitive_files", False)
    findings.append(Finding("Endpoint & Data Hygiene", "No exposed sensitive files in shares", passed, 10,
                             10 if passed else 0, "Clean" if passed else "Sensitive-looking files found in scanned shares"))

    passed = endpoint_data.get("backup_evidence_present", False)
    findings.append(Finding("Endpoint & Data Hygiene", "Backup/recovery evidence present", passed, 8,
                             8 if passed else 0, "Backup evidence found" if passed else "No backup evidence detected"))

    passed = endpoint_data.get("logging_enabled", False)
    findings.append(Finding("Endpoint & Data Hygiene", "Logging enabled", passed, 7,
                             7 if passed else 0, "Logging active" if passed else "Logging not detected"))
    return findings


def generate_score_report(org_name, scan_result, access_data, vuln_data, endpoint_data, anomaly_flag) -> ScoreReport:
    report = ScoreReport(org_name=org_name)
    report.findings.extend(score_network_security(scan_result))
    report.findings.extend(score_access_control(access_data, anomaly_flag))
    report.findings.extend(score_patch_management(vuln_data))
    report.findings.extend(score_endpoint_hygiene(endpoint_data))
    return report
