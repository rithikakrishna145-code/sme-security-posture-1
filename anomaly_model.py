"""
anomaly_model.py

Isolation Forest-based anomaly detection for login/access patterns.
"""

import json
import pandas as pd
from sklearn.ensemble import IsolationForest

KNOWN_IP_PREFIX = "192.168.1."


def engineer_features(login_logs):
    df = pd.DataFrame(login_logs)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour_of_day"] = df["timestamp"].dt.hour
    df["is_known_ip"] = df["ip"].str.startswith(KNOWN_IP_PREFIX).astype(int)
    df["login_success"] = df["success"].astype(int)
    freq = df["user"].value_counts()
    df["user_login_frequency"] = df["user"].map(freq)
    return df


def train_and_score(login_logs, contamination=0.05):
    df = engineer_features(login_logs)
    feature_cols = ["hour_of_day", "is_known_ip", "login_success", "user_login_frequency"]
    X = df[feature_cols]
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    predictions = model.fit_predict(X)
    df["is_anomaly"] = predictions == -1
    df["anomaly_score"] = model.decision_function(X)
    return df, model


def evaluate_against_ground_truth(df):
    if "is_anomaly_ground_truth" not in df.columns:
        return None
    tp = ((df["is_anomaly"]) & (df["is_anomaly_ground_truth"])).sum()
    fp = ((df["is_anomaly"]) & (~df["is_anomaly_ground_truth"])).sum()
    fn = ((~df["is_anomaly"]) & (df["is_anomaly_ground_truth"])).sum()
    tn = ((~df["is_anomaly"]) & (~df["is_anomaly_ground_truth"])).sum()
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    return {"true_positives": int(tp), "false_positives": int(fp), "false_negatives": int(fn),
            "true_negatives": int(tn), "precision": round(precision, 3), "recall": round(recall, 3)}


def org_has_recent_anomaly(df, lookback_events=40):
    recent = df.sort_values("timestamp").tail(lookback_events)
    return bool(recent["is_anomaly"].any())


if __name__ == "__main__":
    with open("data/raw/synthetic_orgs.json") as f:
        orgs = json.load(f)
    for org in orgs:
        df, model = train_and_score(org["login_logs"])
        eval_result = evaluate_against_ground_truth(df)
        anomaly_flag = org_has_recent_anomaly(df)
        print(f"\n{org['org_name']} ({org['risk_level']} risk)")
        print(f"  Anomalies flagged: {df['is_anomaly'].sum()} / {len(df)} events")
        print(f"  Recent anomaly flag: {anomaly_flag}")
        if eval_result:
            print(f"  precision={eval_result['precision']}, recall={eval_result['recall']}")
