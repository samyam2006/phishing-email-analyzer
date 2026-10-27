# phishing-email-analyzer

Python script that looks at a saved email (.eml) and tells you if it's probably phishing and why.

I wanted something that does the same first checks you'd do by hand when someone forwards a sketchy email to the help desk: are SPF/DKIM/DMARC passing, does the sender actually match who they say they are, where do the links really go, is the attachment something dangerous. 

```
python analyzer.py samples/phish_paypal.eml
```

```
============================================================
 phish_paypal.eml
============================================================
 Subject:     Urgent: Your account has been suspended
 From:        PayPal Security <service@paypa1-security.com>
 Reply-To:    support-desk@protonmail.com
 Return-Path: bounce@mailer-xq7.ru
 SPF/DKIM/DMARC: fail / none / fail
 Links: 3  Attachments: 0
------------------------------------------------------------
  [HIGH  ] SPF failed (fail) (+20)
  [HIGH  ] DMARC failed (fail) (+30)
  [HIGH  ] Reply-To domain (protonmail.com) differs from From domain (paypa1-security.com) (+20)
  [HIGH  ] Display name says "PayPal Security" but email is from paypa1-security.com (+25)
  [HIGH  ] Sender domain paypa1-security.com is a look-alike of "paypal" (+25)
  [HIGH  ] Link text shows "https://www.paypal.com/signin" but goes to 185.220.101.44 (+25)
  ...
------------------------------------------------------------
 Score: 223  ->  LIKELY PHISHING
```

## What it checks

- SPF / DKIM / DMARC results from the Authentication-Results header
- Reply-To or Return-Path on a different domain than From
- display name pretending to be a brand, like "PayPal" <someone@random.ru>
- look-alike domains (paypa1.com, arnazon.com, micr0soft)
- links that use an IP address, URL shorteners, punycode, sketchy TLDs like .xyz/.top
- link text that shows one site but actually goes somewhere else
- attachments: .exe/.js/.iso etc, double extensions like invoice.pdf.exe, renamed Windows programs
- urgency stuff ("verify your account within 24 hours")

Every finding adds points. 60+ is LIKELY PHISHING, 25-59 is SUSPICIOUS, under that is LIKELY SAFE. The scores are just my best guess at weighting, so it's meant to help triage, not replace looking at the email yourself.

Other options:

```
python analyzer.py email.eml --json     # json output
python analyzer.py samples/*.eml        # multiple files
python analyzer.py email.eml --vt       # also check VirusTotal
```

Exits with code 2 if anything comes back as phishing.

## VirusTotal

Optional. Get a free API key from virustotal.com, then:

```
export VT_API_KEY=yourkey        # or $env:VT_API_KEY="yourkey" in PowerShell
python analyzer.py email.eml --vt
```

It checks each link and the SHA-256 of each attachment. Free tier is 4 requests a minute so it's slow on emails with lots of links.

## Samples

There are 3 in `samples/` — a normal GitHub newsletter (comes back safe), a fake PayPal phish, and a fake invoice with an `Invoice_88231.pdf.exe` attachment. The "exe" is just a 512 byte placeholder, not actual malware. Domains and IPs are made up.

To test your own: in Gmail it's ⋮ → Download message, in Outlook just drag the email into a folder. Spam folder is a good place to find real ones.

## Tests

```
pip install -r requirements-dev.txt
pytest
```

They also run on GitHub Actions on every push.

## Known issues / todo

- base_domain just takes the last two parts so .co.uk domains get treated wrong
- forwarded emails show the forwarder's SPF/DKIM results, not the original
- want to add WHOIS domain age (brand new domains are a big red flag) and maybe MITRE ATT&CK tags for each finding
