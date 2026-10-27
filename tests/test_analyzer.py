import json
import os
import sys
from email.message import EmailMessage

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import analyzer  # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")


def sample(name):
    return os.path.join(SAMPLES, name)


def messages(report):
    return " | ".join(f.message for f in report.findings)


def write_eml(tmp_path, **headers_and_body):
    # makes a quick .eml for testing one thing
    msg = EmailMessage()
    body = headers_and_body.pop("body", "Hello")
    html = headers_and_body.pop("html", None)
    for k, v in headers_and_body.items():
        msg[k.replace("_", "-")] = v
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    path = tmp_path / "test.eml"
    path.write_bytes(bytes(msg))
    return str(path)


def test_legit_email_is_safe():
    r = analyzer.analyze(sample("legit_newsletter.eml"))
    assert r.verdict == "LIKELY SAFE"
    assert r.findings == []


def test_paypal_phish_is_flagged():
    r = analyzer.analyze(sample("phish_paypal.eml"))
    assert r.verdict == "LIKELY PHISHING"
    text = messages(r)
    assert "SPF failed" in text
    assert "DMARC failed" in text
    assert "Reply-To domain" in text
    assert "raw IP address" in text
    assert "Link text shows" in text
    assert "look-alike" in text


def test_invoice_attachment_is_flagged():
    r = analyzer.analyze(sample("suspicious_invoice.eml"))
    assert r.verdict == "LIKELY PHISHING"
    assert len(r.attachments) == 1
    assert len(r.attachments[0]["sha256"]) == 64
    assert "Double extension" in messages(r)


def test_auth_results_parsing(tmp_path):
    path = write_eml(tmp_path, From="a@b.com",
                     Authentication_Results="mx; spf=pass; dkim=fail; dmarc=pass")
    auth = analyzer.parse_auth_results(analyzer.load_email(path))
    assert auth == {"spf": "pass", "dkim": "fail", "dmarc": "pass"}


def test_display_name_brand_spoof(tmp_path):
    path = write_eml(tmp_path, From='"Microsoft Support" <help@random-mail.net>')
    r = analyzer.analyze(path)
    assert 'Display name says "Microsoft Support"' in messages(r)


def test_real_brand_domain_not_flagged(tmp_path):
    path = write_eml(tmp_path, From='"Microsoft" <account@microsoft.com>',
                     Authentication_Results="mx; spf=pass; dkim=pass; dmarc=pass")
    r = analyzer.analyze(path)
    assert r.findings == []


@pytest.mark.parametrize("domain,brand", [
    ("paypa1.com", "paypal"),
    ("arnazon-orders.com", "amazon"),
    ("micr0soft-login.net", "microsoft"),
])
def test_lookalike_domains(domain, brand):
    assert analyzer.lookalike_brand(domain) == brand


@pytest.mark.parametrize("domain", ["paypal.com", "github.com", "example.edu"])
def test_real_domains_are_not_lookalikes(domain):
    assert analyzer.lookalike_brand(domain) is None


@pytest.mark.parametrize("url,expected", [
    ("http://10.0.0.5/login", "raw IP address"),
    ("https://bit.ly/abc", "URL shortener"),
    ("https://xn--pypal-4ve.com/", "punycode"),
    ("https://secure-login.top/", "high-risk TLD"),
    ("https://paypal.com@evil.example/", "behind '@'"),
])
def test_url_checks(url, expected):
    problems = analyzer.analyze_url(url)
    assert any(expected in msg for _, msg, _ in problems)


def test_safe_url_has_no_problems():
    assert analyzer.analyze_url("https://github.com/explore") == []


def test_mismatched_link_text(tmp_path):
    path = write_eml(tmp_path, From="a@shop.com",
                     html='<a href="https://evil.example/x">https://www.chase.com</a>')
    assert "Link text shows" in messages(analyzer.analyze(path))


def test_urgency_language(tmp_path):
    path = write_eml(tmp_path, From="a@b.com", Subject="Final notice",
                     body="Act now or your account will be suspended. Click here.")
    assert "urgency" in messages(analyzer.analyze(path)).lower()


def test_cli_json_output(capsys):
    code = analyzer.main([sample("phish_paypal.eml"), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 2
    assert data["verdict"] == "LIKELY PHISHING"
    assert data["score"] > 60


def test_cli_exit_code_safe(capsys):
    assert analyzer.main([sample("legit_newsletter.eml"), "--no-color"]) == 0


def test_vt_without_key_is_skipped(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    r = analyzer.analyze(sample("legit_newsletter.eml"), use_vt=True)
    assert "VT_API_KEY not set" in messages(r)
    assert r.verdict == "LIKELY SAFE"
