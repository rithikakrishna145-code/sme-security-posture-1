# SME Security Posture Monitoring Platform — PSAIAC_277

## Step-by-Step: Getting This Running On Your Machine

### Step 1 — Install Python (if not already installed)
You need Python 3.10 or newer. Check with:
```
python3 --version
```
If you don't have it, download from python.org.

### Step 2 — Unzip this project and open a terminal in that folder
```
cd sme-security-posture
```

### Step 3 — Install the required libraries
```
pip install -r requirements.txt
```
This installs pandas, scikit-learn, streamlit, and everything else needed.
If `pip` doesn't work, try `pip3` instead.

### Step 4 — Generate the synthetic organization data
```
python src/data_generator.py
```
This creates `data/raw/synthetic_orgs.json` — three simulated companies
(low, medium, and high security risk) with realistic scan results and
14 days of login logs each.

**Expected output:**
```
SecureStitch Apparel Pvt Ltd (low risk): 281 events, 3 true anomalies
QuickBooks Retail Co (medium risk): 331 events, 3 true anomalies
LegacyWare Traders (high risk): 364 events, 3 true anomalies
```

### Step 5 — Run the full scoring + ML pipeline
```
python src/run_pipeline.py
```
This runs the Isolation Forest anomaly detection, then the CIS scoring
engine, and saves the final results to `data/processed/posture_reports.json`.

**Expected output:** a posture score (0-100) and rating for each of the
three organizations, with a category-by-category breakdown.

### Step 6 — Launch the dashboard
```
streamlit run dashboard/app.py
```
This opens a browser window automatically (usually at `http://localhost:8501`).
You can switch between the three organizations in the sidebar and see the
score, findings, and anomaly detection results visually.

**This is what you demo live for Review-3.**

---

## What Each File Does (for your own understanding, and for viva questions)

| File | What it does |
|---|---|
| `src/data_generator.py` | Creates realistic fake scan/log data for 3 simulated companies |
| `src/scoring_engine.py` | The CIS-benchmark scoring logic — 4 categories, 14 checks total |
| `src/anomaly_model.py` | The Isolation Forest ML model — detects unusual logins |
| `src/run_pipeline.py` | Connects everything together — data → ML → scoring → saved results |
| `dashboard/app.py` | The Streamlit web dashboard — what you show the panel live |

## Running It Again After Changes
If you or a teammate edits `data_generator.py`, `scoring_engine.py`, or
`anomaly_model.py`, just re-run Steps 4 and 5 to regenerate results, then
Step 6 to see them in the dashboard.

## Before Review-3
- [ ] Every team member should run Steps 1-6 themselves at least once —
      don't let only one person know how to run it
- [ ] Practice narrating what's happening at each step during the live demo
- [ ] Push this whole folder to your GitHub repo (`git init`, `git add .`,
      `git commit -m "initial implementation"`, then push) — this is
      graded separately and should show commits from multiple team members
- [ ] Have a backup: take screenshots of the dashboard in case of
      wifi/projector issues on the day
