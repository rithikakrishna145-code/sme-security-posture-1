"""
run_pipeline.py

End-to-end pipeline: loads org data -> runs anomaly detection -> feeds result
into the CIS scoring engine -> produces final posture reports for all orgs.
"""

import json
from anomaly_model import train_and_score, org_has_recent_anomaly, evaluate_against_ground_truth
from scoring_engine import generate_score_report


def run_full_pipeline(orgs_path="data/raw/synthetic_orgs.json"):
    with open(orgs_path) as f:
        orgs = json.load(f)
    reports = []
    for org in orgs:
        df, model = train_and_score(org["login_logs"])
        anomaly_flag = org_has_recent_anomaly(df)
        ml_validation = evaluate_against_ground_truth(df)
        report = generate_score_report(
            org_name=org["org_name"], scan_result=org["scan_result"],
            access_data=org["access_data"], vuln_data=org["vuln_data"],
            endpoint_data=org["endpoint_data"], anomaly_flag=anomaly_flag,
        )
        result = report.to_dict()
        result["ml_validation"] = ml_validation
        result["declared_risk_level"] = org["risk_level"]
        reports.append(result)

    with open("data/processed/posture_reports.json", "w") as f:
        json.dump(reports, f, indent=2)
    return reports


if __name__ == "__main__":
    reports = run_full_pipeline()
    print("=" * 70)
    print("PIPELINE RESULTS SUMMARY")
    print("=" * 70)
    for r in reports:
        print(f"\n{r['org_name']}")
        print(f"  Declared risk level: {r['declared_risk_level']}")
        print(f"  Posture Score: {r['total_score']}/{r['max_score']} — {r['rating']}")
        for cat, vals in r["category_breakdown"].items():
            print(f"    {cat}: {vals['awarded']}/{vals['possible']}")
    print("\nSaved to data/processed/posture_reports.json")
