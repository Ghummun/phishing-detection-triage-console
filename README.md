# Phishing Email Triage Console

A Flask-based tool that analyzes raw email content (.eml files or pasted source) and produces a risk score by checking email authentication results, sender/reply-to mismatches, suspicious URL patterns, and urgency language — the same checks a help desk or SOC analyst runs through manually when a user reports a suspicious email.

## Why I built this

Phishing triage is one of the most common ticket types a help desk or SOC analyst handles. This tool automates the checklist an analyst works through by hand: verifying SPF/DKIM/DMARC results, spotting domain spoofing, and flagging credential-harvesting link patterns — then surfaces it all as a single risk score with clear justification.

## What it checks

- **SPF / DKIM / DMARC authentication results** — parsed from the email's `Authentication-Results` header
- **Reply-To vs. From domain mismatch** — a classic phishing tactic where replies route to an attacker-controlled domain
- **Suspicious URL patterns** — raw IP addresses used as links, excessive subdomains, credential-harvesting keywords
- **Urgency language** — subject lines using pressure tactics ("verify immediately," "account suspended")

Each check contributes to a 0–100 risk score, bucketed into LOW / MEDIUM / HIGH risk.

## Tech stack

- Python 3 (standard library `email` module for parsing)
- Flask (web interface)

## Running it locally

```bash
pip install flask
python app.py
```

Visit `http://127.0.0.1:5000`. Paste raw email source or upload a `.eml` file.

## Sample results

| Sample | Score | Risk Level | Key flags |
|---|---|---|---|
| `phishing_example.eml` | 100 | HIGH | SPF/DKIM/DMARC all failed, Reply-To mismatch, raw IP link, urgency language |
| `legitimate_example.eml` | 0 | LOW | All authentication checks passed, no suspicious indicators |

## Screenshots

**High-risk phishing email detected:**
![Phishing result](screenshots/screenshot_phishing_result.png)

**Legitimate email correctly scored as low risk:**
![Legitimate result](screenshots/screenshot_legitimate_result.png)

## Project structure
