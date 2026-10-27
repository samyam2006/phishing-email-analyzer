# phishing email analyzer
# usage: python analyzer.py email.eml [--json] [--vt] [--no-color]

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc"]

# tlds that come up a lot in phishing reports
BAD_TLDS = ["zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf",
            "ga", "work", "support", "rest", "fit", "cam", "icu", "buzz"]

BAD_EXTS = ["exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "hta", "iso",
            "img", "lnk", "msi", "jar", "docm", "xlsm", "pptm", "html", "htm", "one", "wsf", "cpl"]

URGENT_WORDS = [
    "verify your account", "account will be suspended", "account has been suspended",
    "unusual activity", "suspicious activity", "confirm your identity",
    "update your payment", "within 24 hours", "within 48 hours", "act now",
    "immediately", "urgent", "final notice", "click here", "login to restore",
    "password will expire", "your account has been locked", "wire transfer",
    "gift card", "invoice attached", "overdue payment",
]

# brands that get impersonated a lot -> their real domains
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "office 365": ["microsoft.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "chase": ["chase.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "irs": ["irs.gov"],
}

# characters scammers swap in to fake a domain (paypa1, arnazon, etc)
SWAPS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a")]

url_re = re.compile(r"""https?://[^\s"'<>)\]]+""", re.I)


class Finding:
    def __init__(self, category, severity, message, points):
        self.category = category
        self.severity = severity
        self.message = message
        self.points = points


class Report:
    def __init__(self, file):
        self.file = file
        self.subject = ""
        self.from_address = ""
        self.from_display_name = ""
        self.reply_to = ""
        self.return_path = ""
        self.auth = {}
        self.urls = []
        self.attachments = []
        self.findings = []
        self.score = 0
        self.verdict = ""

    def add(self, category, severity, message, points):
        self.findings.append(Finding(category, severity, message, points))
        self.score += points

    def to_dict(self):
        d = dict(self.__dict__)
        d["findings"] = [f.__dict__ for f in self.findings]
        return d


def get_domain(address):
    addr = parseaddr(address or "")[1]
    if "@" not in addr:
        return ""
    return addr.split("@")[-1].lower()


def base_domain(host):
    # just takes the last 2 parts, mail.paypal.com -> paypal.com
    # doesn't handle stuff like .co.uk but good enough for now
    parts = (host or "").lower().strip(".").split(".")
    return ".".join(parts[-2:])


def is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def lookalike_brand(domain):
    raw = domain.lower().replace("-", "").replace(".", "")
    fixed = raw
    for fake, real in SWAPS:
        fixed = fixed.replace(fake, real)
    if fixed == raw:
        return None
    for brand, real_domains in BRANDS.items():
        name = brand.replace(" ", "")
        # skip short names like "ups", too many false positives
        if len(name) >= 4 and name in fixed and name not in raw and base_domain(domain) not in real_domains:
            return brand
    return None


# pulls out every <a href> and the text shown for it
class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.href = None
        self.text = ""

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.href = dict(attrs).get("href")
            self.text = ""

    def handle_data(self, data):
        if self.href is not None:
            self.text += data

    def handle_endtag(self, tag):
        if tag == "a" and self.href is not None:
            self.links.append((self.href.strip(), self.text.strip()))
            self.href = None


def load_email(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_body(msg):
    text = ""
    html = ""
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            # some emails have broken charsets
            content = part.get_payload(decode=True).decode("utf-8", "replace")
        if ctype == "text/plain":
            text += content + "\n"
        else:
            html += content + "\n"
    return text, html


def parse_auth_results(msg):
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    headers = msg.get_all("Authentication-Results") or []
    all_headers = " ".join(str(h) for h in headers).lower()
    for key in results:
        m = re.search(r"\b" + key + r"=(\w+)", all_headers)
        if m:
            results[key] = m.group(1)

    # some servers only add Received-SPF
    if results["spf"] == "none":
        m = re.match(r"\s*(\w+)", str(msg.get("Received-SPF", "")).lower())
        if m:
            results["spf"] = m.group(1)
    return results


def check_auth(report, msg):
    report.auth = parse_auth_results(msg)
    for key, result in report.auth.items():
        if result in ("fail", "permerror"):
            pts = 30 if key == "dmarc" else 20
            report.add("auth", "high", f"{key.upper()} failed ({result})", pts)
        elif result in ("softfail", "temperror", "neutral"):
            report.add("auth", "medium", f"{key.upper()} result was {result}", 10)
        elif result == "none":
            report.add("auth", "low", f"No {key.upper()} result found", 5)


def check_sender(report, msg):
    name, addr = parseaddr(str(msg.get("From", "")))
    report.from_display_name = name
    report.from_address = addr
    report.reply_to = parseaddr(str(msg.get("Reply-To", "")))[1]
    report.return_path = parseaddr(str(msg.get("Return-Path", "")))[1]

    from_dom = base_domain(get_domain(addr))

    if report.reply_to:
        reply_dom = base_domain(get_domain(report.reply_to))
        if reply_dom and reply_dom != from_dom:
            report.add("sender", "high", f"Reply-To domain ({reply_dom}) differs from From domain ({from_dom})", 20)

    if report.return_path:
        rp_dom = base_domain(get_domain(report.return_path))
        if rp_dom and rp_dom != from_dom:
            report.add("sender", "medium", f"Return-Path domain ({rp_dom}) differs from From domain ({from_dom})", 10)

    # "PayPal Security" <someone@random.ru>
    for brand, real_domains in BRANDS.items():
        if re.search(r"\b" + re.escape(brand) + r"\b", name.lower()):
            if from_dom not in real_domains:
                report.add("sender", "high", f'Display name says "{name}" but email is from {from_dom}', 25)
            break

    brand = lookalike_brand(get_domain(addr))
    if brand:
        report.add("sender", "high", f'Sender domain {get_domain(addr)} is a look-alike of "{brand}"', 25)

    # "support@paypal.com" <someone@random.ru>
    m = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", name)
    if m and base_domain(m.group(1)) != from_dom:
        report.add("sender", "high", f"Display name contains a different address ({m.group(0)})", 20)


def analyze_url(url):
    problems = []
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return problems

    if is_ip(host):
        problems.append(("high", f"Link uses a raw IP address: {url}", 20))
    if host in SHORTENERS:
        problems.append(("medium", f"Link uses a URL shortener: {url}", 10))
    if host.startswith("xn--") or ".xn--" in host:
        problems.append(("high", f"Link uses punycode (look-alike domain): {host}", 20))
    if host.split(".")[-1] in BAD_TLDS:
        problems.append(("medium", f"Link uses a high-risk TLD (.{host.split('.')[-1]}): {host}", 10))
    if "@" in parsed.netloc:
        # https://paypal.com@evil.com actually goes to evil.com
        problems.append(("high", f"Link hides its real host behind '@': {url}", 20))
    if parsed.scheme == "http":
        problems.append(("low", f"Link is not encrypted (http): {host}", 3))
    if host.count("-") >= 3 or host.count(".") >= 4:
        problems.append(("low", f"Link host looks unusually long: {host}", 5))

    brand = lookalike_brand(host)
    if brand:
        problems.append(("high", f'Link host {host} is a look-alike of "{brand}"', 25))

    for brand, real_domains in BRANDS.items():
        if brand.replace(" ", "") in host.replace("-", "") and base_domain(host) not in real_domains:
            problems.append(("high", f'Link mentions "{brand}" but goes to {base_domain(host)}', 20))
            break

    return problems


def check_links(report, text, html):
    urls = []

    if html:
        p = LinkParser()
        p.feed(html)
        for href, shown in p.links:
            if not href.lower().startswith("http"):
                continue
            urls.append(href)
            # does the link text look like a different website than where it goes?
            m = url_re.search(shown) or re.search(r"\b[\w-]+\.[a-z]{2,}\b", shown.lower())
            if m:
                shown_url = m.group(0)
                if "://" not in shown_url:
                    shown_url = "http://" + shown_url
                shown_host = urlparse(shown_url).hostname or ""
                real_host = urlparse(href).hostname or ""
                if shown_host and base_domain(shown_host) != base_domain(real_host):
                    report.add("links", "high", f'Link text shows "{shown}" but goes to {real_host}', 25)

    urls += url_re.findall(text)
    urls += url_re.findall(html)

    for u in urls:
        u = u.rstrip(".,;")
        if u not in report.urls:
            report.urls.append(u)

    for url in report.urls:
        for sev, msg_text, pts in analyze_url(url):
            report.add("links", sev, msg_text, pts)


def check_attachments(report, msg):
    for part in msg.iter_attachments():
        name = part.get_filename() or "(no name)"
        data = part.get_payload(decode=True) or b""
        report.attachments.append({
            "filename": name,
            "content_type": part.get_content_type(),
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })

        pieces = name.lower().split(".")
        ext = pieces[-1] if len(pieces) > 1 else ""
        if ext in BAD_EXTS:
            report.add("attachments", "high", f"Risky attachment type: {name}", 25)
        # invoice.pdf.exe
        if len(pieces) >= 3 and pieces[-2] in ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"]:
            report.add("attachments", "high", f"Double extension (disguised file): {name}", 25)
        # windows exes start with MZ, catches renamed ones
        if data[:2] == b"MZ" and ext not in ["exe", "dll", "scr"]:
            report.add("attachments", "high", f"{name} is actually a Windows program (MZ header)", 30)


def check_language(report, subject, text, html):
    everything = (subject + " " + text + " " + re.sub(r"<[^>]+>", " ", html)).lower()
    found = [w for w in URGENT_WORDS if w in everything]
    if found:
        sev = "medium" if len(found) >= 2 else "low"
        report.add("language", sev, "Pressure / urgency phrases: " + ", ".join(found), min(5 * len(found), 20))

    asks_for_info = re.search(r"(password|ssn|social security|card number|login credentials)", everything)
    if asks_for_info and re.search(r"(enter|confirm|verify|provide|update)", everything):
        report.add("language", "medium", "Asks the reader to enter or confirm sensitive info", 10)


def vt_get(endpoint, key):
    req = urllib.request.Request("https://www.virustotal.com/api/v3/" + endpoint, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:  # VT has never seen it
            return None
        raise


def check_virustotal(report, key):
    to_check = [("url", u) for u in report.urls] + [("file", a["sha256"]) for a in report.attachments]
    for kind, value in to_check:
        if kind == "url":
            # VT wants the url base64 encoded without padding
            endpoint = "urls/" + base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        else:
            endpoint = "files/" + value
        try:
            data = vt_get(endpoint, key)
        except Exception as e:
            report.add("reputation", "info", f"VirusTotal lookup failed for {value}: {e}", 0)
            continue
        if data is None:
            report.add("reputation", "info", f"VirusTotal has no record of {value}", 0)
            continue
        bad = data["data"]["attributes"].get("last_analysis_stats", {}).get("malicious", 0)
        if bad:
            report.add("reputation", "high", f"VirusTotal: {bad} engines flag {value} as malicious", 40)


def get_verdict(score):
    if score >= 60:
        return "LIKELY PHISHING"
    elif score >= 25:
        return "SUSPICIOUS"
    return "LIKELY SAFE"


def analyze(path, use_vt=False):
    msg = load_email(path)
    report = Report(path)
    report.subject = str(msg.get("Subject", ""))
    text, html = get_body(msg)

    check_auth(report, msg)
    check_sender(report, msg)
    check_links(report, text, html)
    check_attachments(report, msg)
    check_language(report, report.subject, text, html)

    if use_vt:
        key = os.environ.get("VT_API_KEY")
        if key:
            check_virustotal(report, key)
        else:
            report.add("reputation", "info", "VT_API_KEY not set, skipped VirusTotal", 0)

    report.verdict = get_verdict(report.score)
    return report


RED, YELLOW, CYAN, GRAY, RESET = "\033[91m", "\033[93m", "\033[96m", "\033[90m", "\033[0m"
SEV_COLOR = {"high": RED, "medium": YELLOW, "low": CYAN, "info": GRAY}
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def print_report(r, color=True):
    def paint(s, c):
        return c + s + RESET if color else s

    print("=" * 60)
    print(" " + os.path.basename(r.file))
    print("=" * 60)
    print(" Subject:     " + r.subject)
    print(f" From:        {r.from_display_name} <{r.from_address}>")
    if r.reply_to:
        print(" Reply-To:    " + r.reply_to)
    if r.return_path:
        print(" Return-Path: " + r.return_path)
    print(f" SPF/DKIM/DMARC: {r.auth['spf']} / {r.auth['dkim']} / {r.auth['dmarc']}")
    print(f" Links: {len(r.urls)}  Attachments: {len(r.attachments)}")
    for a in r.attachments:
        print(f"   {a['filename']} ({a['size_bytes']} bytes) sha256={a['sha256'][:16]}...")
    print("-" * 60)

    if not r.findings:
        print(" Nothing suspicious found.")
    for f in sorted(r.findings, key=lambda f: SEV_ORDER[f.severity]):
        tag = paint("[" + f.severity.upper().ljust(6) + "]", SEV_COLOR[f.severity])
        print(f"  {tag} {f.message} (+{f.points})")

    print("-" * 60)
    if r.verdict == "LIKELY PHISHING":
        c = RED
    elif r.verdict == "SUSPICIOUS":
        c = YELLOW
    else:
        c = CYAN
    print(f" Score: {r.score}  ->  {paint(r.verdict, c)}")
    print()


def main(args=None):
    ap = argparse.ArgumentParser(description="check .eml files for phishing")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", action="store_true", help="print json instead")
    ap.add_argument("--vt", action="store_true", help="check links/attachments on virustotal (needs VT_API_KEY)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(args)

    reports = [analyze(f, args.vt) for f in args.files]

    if args.json:
        out = [r.to_dict() for r in reports]
        if len(out) == 1:
            out = out[0]
        print(json.dumps(out, indent=2))
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        for r in reports:
            print_report(r, use_color)

    # exit 2 if something looks like phishing, handy for scripts
    for r in reports:
        if r.verdict == "LIKELY PHISHING":
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
