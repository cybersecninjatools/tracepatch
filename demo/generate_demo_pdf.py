#!/usr/bin/env python3
"""
Generates a synthetic pen test report PDF for demo purposes.
Uses real, publicly-known CVEs but entirely fake org/host/finding data.
Output is formatted to parse correctly through pdf_parser.py's heuristics.
"""
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

FINDINGS = [
    ("Outdated Apache HTTP Server", "Critical", "CVE-2021-41773",
     "The web server at demo-web-01.example.local is running Apache 2.4.49, "
     "which is vulnerable to a path traversal and remote code execution flaw. "
     "An attacker could access files outside the intended document root."),
    ("Unpatched OpenSSL Library", "High", "CVE-2022-0778",
     "demo-app-02.example.local uses a version of OpenSSL affected by an "
     "infinite loop denial-of-service vulnerability in BN_mod_sqrt()."),
    ("Weak TLS Cipher Suites Enabled", "Medium", "CVE-2016-2183",
     "demo-lb-01.example.local supports 3DES cipher suites, which are "
     "vulnerable to the SWEET32 birthday attack against long-lived connections."),
    ("Default Credentials on Admin Panel", "Critical", "CVE-2023-27997",
     "The management interface at demo-fw-01.example.local was found "
     "accessible with default vendor credentials still in place."),
    ("Missing HTTP Security Headers", "Low", "",
     "demo-web-01.example.local does not set X-Frame-Options or "
     "Content-Security-Policy headers, increasing clickjacking risk."),
]

def generate(output_path="demo_pentest_report.pdf"):
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter

    # Cover page
    c.setFont("Helvetica-Bold", 20)
    c.drawString(1*inch, height - 1.5*inch, "External Penetration Test Report")
    c.setFont("Helvetica", 12)
    c.drawString(1*inch, height - 2*inch, "Prepared for: Demo Security Corp")
    c.drawString(1*inch, height - 2.3*inch, "Prepared by: Redacted Security Partners")
    c.drawString(1*inch, height - 2.6*inch, "Report Date: 2026-07-01")
    c.drawString(1*inch, height - 2.9*inch, "Classification: Confidential")
    c.showPage()

    # Table of contents (should be skipped by parser)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, height - 1*inch, "Table of Contents")
    c.setFont("Helvetica", 11)
    c.drawString(1*inch, height - 1.4*inch, "1. Executive Summary")
    c.drawString(1*inch, height - 1.6*inch, "2. Scope")
    c.drawString(1*inch, height - 1.8*inch, "3. Findings")
    c.showPage()

    # Executive summary (should be skipped)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, height - 1*inch, "Executive Summary")
    c.setFont("Helvetica", 10)
    c.drawString(1*inch, height - 1.4*inch,
                 "This engagement identified several vulnerabilities of varying severity.")
    c.showPage()

    # Findings pages
    y = height - 1*inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, y, "Findings")
    y -= 0.4*inch

    for title, risk, cve, desc in FINDINGS:
        if y < 2*inch:
            c.showPage()
            y = height - 1*inch

        c.setFont("Helvetica-Bold", 12)
        c.drawString(1*inch, y, title)
        y -= 0.25*inch

        c.setFont("Helvetica-Bold", 10)
        risk_line = f"Risk: {risk}"
        if cve:
            risk_line += f"   {cve}"
        c.drawString(1*inch, y, risk_line)
        y -= 0.3*inch

        c.setFont("Helvetica", 9)
        # wrap description manually at ~90 chars
        words = desc.split()
        line = ""
        for w in words:
            if len(line) + len(w) < 90:
                line += w + " "
            else:
                c.drawString(1*inch, y, line.strip())
                y -= 0.2*inch
                line = w + " "
        if line:
            c.drawString(1*inch, y, line.strip())
            y -= 0.4*inch

    c.save()
    print(f"Generated: {output_path}")

if __name__ == '__main__':
    generate()
