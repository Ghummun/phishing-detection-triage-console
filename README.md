# Phishing Email Triage Console

A Flask-based tool that analyzes raw email content and produces a risk score by checking SPF/DKIM/DMARC authentication, sender mismatches, suspicious URL patterns, and urgency language — the same checks a help desk or SOC analyst runs through when a user reports a suspicious email.

## What it checks

- SPF / DKIM / DMARC authentication results
- Reply-To vs. From domain mismatch
- Suspicious URL patterns (raw IPs, excessive subdomains, credential-harvesting keywords)
- Urgency language in subject lines

## Tech stack

Python 3, Flask

## Running it locally

```bash
pip install flask
python app.py
```

## Sample results

| Sample | Score | Risk Level |
|---|---|---|
| phishing_example.eml | 100 | HIGH |
| legitimate_example.eml | 0 | LOW |

## Screenshots

![Phishing result](screenshot_phishing_result.png)

![Legitimate result](screenshot_legitimate_result.png)
