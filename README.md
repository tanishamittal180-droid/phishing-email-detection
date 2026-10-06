# Phishing Email Detection & Awareness Dashboard

A defensive, explainable cybersecurity project for analyzing **synthetic or authorized email data**. It combines sender analysis, content/social-engineering signals, static URL inspection, attachment filename analysis, a transparent risk engine, optional TF-IDF + Logistic Regression ML, SQLite history, analytics, and a security-awareness lab.

> **Safety:** This project never sends phishing email, never visits submitted URLs, never executes attachments, and does not collect credentials. Use only synthetic, fictional, or authorized data. The supplied demo uses reserved/example domains and IP ranges.

## Features
- Email analyzer: sender, display name, subject, body, attachment filename
- Static URL analyzer: scheme, hostname, IP use, subdomains, length, keywords, shorteners
- Social-engineering detection: urgency, fear, financial pressure, credential requests, rewards, personal information, generic greetings
- Explainable 0–100 rule score with LOW / MODERATE / SUSPICIOUS / HIGH classifications
- Actionable recommendations
- Safe `.txt` / `.eml` upload endpoint
- SQLite analysis history and indicator tables
- Dashboard KPIs and charts
- Awareness lessons + Before You Click checklist
- 600-record synthetic dataset generator
- Optional ML training/evaluation with TF-IDF + Logistic Regression
- Automated tests
- GitHub-ready documentation and report materials

## Architecture
User → Browser Dashboard → FastAPI → preprocessing/analyzers → rule risk engine → explainable result → SQLite → dashboard analytics.

ML is an optional offline training layer and is not required to run the dashboard.

## Folder structure
```text
backend/        FastAPI application, analyzers, risk engine, database
frontend/       Zero-build browser dashboard
ml/             Optional ML training/evaluation
 data/          Synthetic dataset generator + generated CSV
models/         Generated ML artifacts (ignored by Git)
tests/          Automated tests
docs/           Architecture, API, testing, GitHub and demo notes
reports/        Academic-style project report
samples/        Safe sample emails
screenshots/    Suggested proof screenshots
```

## Windows installation
```powershell
cd Phishing-Email-Detection-Awareness-Dashboard
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python data\generate_dataset.py
python -m uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```
Open **http://127.0.0.1:8000**.

Optional ML:
```powershell
python ml\train_model.py
python ml\evaluation.py
```
Tests:
```powershell
pytest -q
```

## Linux/macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python data/generate_dataset.py
python -m uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

## Safe demo
Click **Load safe demo** in Email Analyzer. It uses:
- `security-alert@account-check.invalid.test`
- `http://198.51.100.10/verify-account`
- `invoice.pdf.exe`

For a legitimate demo use **Load legitimate demo**, which uses `training@example.org` and an informational workshop reminder.

## API
- `GET /api/health`
- `POST /api/analyze`
- `POST /api/analyze/url`
- `POST /api/analyze/file`
- `GET /api/analyses`
- `GET /api/analyses/{id}`
- `DELETE /api/analyses/{id}`
- `GET /api/dashboard/stats`
- `GET /api/awareness`
- Interactive API docs: `/docs`

### Example request
```json
{
  "sender":"training@example.org",
  "display_name":"Training Team",
  "subject":"Workshop reminder",
  "body":"Hello team, the workshop starts tomorrow.",
  "attachment_name":"",
  "store_history":true
}
```

## Risk scoring
The score is a **project heuristic**, not a universal security standard. Multiple signals are combined and capped at 100. Thresholds should be calibrated with representative validation data before production use.

## ML
The included dataset is synthetic and intentionally simple. ML metrics produced by your machine should be reported from the actual run rather than copied into documentation. Precision, recall, F1 and the confusion matrix are more informative than accuracy alone for imbalanced security data.

## Privacy/security controls
- No automatic URL navigation
- No attachment execution
- File uploads limited by extension and read size in the API path
- Email content is not stored by default; history stores metadata and findings
- Rendered results escape HTML in the browser
- Secrets belong in environment variables
- Production deployment should use authentication, authorization, rate limiting, HTTPS, centralized logging and stronger upload controls

## GitHub
Suggested repository: `Phishing-Email-Detection-Awareness-Dashboard`
Suggested topics: `cybersecurity`, `phishing-detection`, `email-security`, `soc`, `python`, `machine-learning`, `nlp`, `threat-detection`, `security-awareness`, `url-analysis`, `defensive-security`

See `docs/github_strategy.md` for commit and screenshot guidance.

## Disclaimer
This project is designed for cybersecurity education and defensive analysis using synthetic or authorized data.
