import re
import email
from email import policy
from urllib.parse import urlparse


def parse_email(raw_email_bytes):
    msg = email.message_from_bytes(raw_email_bytes, policy=policy.default)
    return msg


def get_header_safe(msg, header_name):
    value = msg.get(header_name, "")
    return str(value)


def check_auth_results(msg):
    auth_header = get_header_safe(msg, "Authentication-Results").lower()
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    spf_match = re.search(r"spf=(\w+)", auth_header)
    if spf_match:
        results["spf"] = spf_match.group(1)

    dkim_match = re.search(r"dkim=(\w+)", auth_header)
    if dkim_match:
        results["dkim"] = dkim_match.group(1)

    dmarc_match = re.search(r"dmarc=(\w+)", auth_header)
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1)

    return results


def extract_from_domain(msg):
    from_header = get_header_safe(msg, "From")
    match = re.search(r"@([\w\.-]+)", from_header)
    return match.group(1).lower() if match else ""


def extract_reply_to_domain(msg):
    reply_to = get_header_safe(msg, "Reply-To")
    match = re.search(r"@([\w\.-]+)", reply_to)
    return match.group(1).lower() if match else ""


def extract_urls(msg):
    urls = set()
    url_pattern = re.compile(r'https?://[^\s"\'<>\)]+')

    if msg.is_multipart():
        parts = msg.walk()
    else:
        parts = [msg]

    for part in parts:
        content_type = part.get_content_type()
        if content_type in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except Exception:
                continue
            for found in url_pattern.findall(content):
                urls.add(found.rstrip(".,;"))

    return list(urls)


def get_url_domains(urls):
    domains = []
    for u in urls:
        try:
            domains.append(urlparse(u).netloc.lower())
        except Exception:
            continue
    return domains


def calculate_risk_score(msg):
    score = 0
    flags = []

    auth = check_auth_results(msg)
    from_domain = extract_from_domain(msg)
    reply_to_domain = extract_reply_to_domain(msg)
    urls = extract_urls(msg)
    url_domains = get_url_domains(urls)

    if auth["spf"] == "fail":
        score += 25
        flags.append("SPF authentication failed")
    elif auth["spf"] == "unknown":
        score += 5
        flags.append("No SPF result found in headers")

    if auth["dkim"] == "fail":
        score += 25
        flags.append("DKIM signature failed")
    elif auth["dkim"] == "unknown":
        score += 5
        flags.append("No DKIM result found in headers")

    if auth["dmarc"] == "fail":
        score += 20
        flags.append("DMARC policy failed")

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        score += 20
        flags.append(f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain})")

    for domain in url_domains:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain):
            score += 15
            flags.append(f"Link uses raw IP address instead of domain: {domain}")
        if domain.count(".") >= 4:
            score += 10
            flags.append(f"Suspicious URL with excessive subdomains: {domain}")
        if any(word in domain for word in ["secure-", "-verify", "account-", "login-"]):
            score += 10
            flags.append(f"URL domain contains suspicious keywords: {domain}")

    subject = get_header_safe(msg, "Subject").lower()
    urgency_words = ["urgent", "verify your account", "suspended", "act now",
                      "immediately", "confirm your identity"]
    for word in urgency_words:
        if word in subject:
            score += 8
            flags.append(f"Subject contains urgency language: '{word}'")
            break

    score = min(score, 100)

    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": score,
        "risk_level": risk_level,
        "flags": flags,
        "auth_results": auth,
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "urls_found": urls,
        "subject": get_header_safe(msg, "Subject"),
        "from_header": get_header_safe(msg, "From"),
    }