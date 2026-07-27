#!/usr/bin/env python3
"""
PDF upload + parsing route — add this to app.py
Uses pdfplumber (pure Python, no external calls).
Heuristic extraction: finds lines that look like findings/vulnerabilities.
"""

import pdfplumber, re, tempfile, os
from flask import request, jsonify

# Add this route to your Flask app:

# @app.route('/api/upload', methods=['POST'])
def upload_pdf():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f = request.files['file']
    if not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': 'PDF files only'}), 400

    # Save to temp file
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name

    try:
        findings = _extract_findings(tmp_path)
        # Create an engagement for this upload
        db = get_db()
        src_name = os.path.splitext(f.filename)[0]
        cur = db.execute(
            "INSERT INTO engagements (name,type,vendor,eng_date) VALUES (?,?,?,?)",
            (src_name, 'External Pen Test', 'Uploaded', str(date.today()))
        )
        eng_id = cur.lastrowid
        db.commit()
        return jsonify({'findings': findings, 'engagement_id': eng_id, 'source': src_name})
    finally:
        os.unlink(tmp_path)


def _extract_findings(pdf_path):
    """
    Heuristic PDF parser. Looks for common patterns in Securin/Nessus/Rapid7 reports:
    - Lines containing risk keywords (Critical/High/Medium/Low) near a title
    - CVE numbers
    - Common vulnerability section headers
    Returns list of {title, risk, description} dicts.
    """
    findings = []
    risk_patterns = {
        'Critical': re.compile(r'\bcritical\b', re.I),
        'High':     re.compile(r'\bhigh\b', re.I),
        'Medium':   re.compile(r'\bmedium\b|\bmoderate\b', re.I),
        'Low':      re.compile(r'\blow\b', re.I),
    }
    cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.I)
    skip_patterns = re.compile(
        r'^(table of contents|executive summary|scope|methodology|appendix|page \d|confidential|prepared for)',
        re.I
    )
    seen_titles = set()

    with pdfplumber.open(pdf_path) as pdf:
        full_text = []
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                full_text.append(text)

    lines = '\n'.join(full_text).split('\n')
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line or len(line) < 8 or skip_patterns.match(line):
            i += 1
            continue

        # Detect risk level in this line or next few lines
        detected_risk = None
        for risk, pat in risk_patterns.items():
            if pat.search(line):
                detected_risk = risk
                break

        # Check for CVE reference
        cves = cve_pattern.findall(line)

        if detected_risk or cves:
            # Try to build a title from this line (clean it up)
            title = re.sub(r'\b(critical|high|medium|low|moderate)\b', '', line, flags=re.I)
            title = re.sub(r'CVE-\d{4}-\d+', '', title)
            title = re.sub(r'\s+', ' ', title).strip(' :-|')
            if len(title) < 5:
                # Use CVE as title fallback
                title = ', '.join(cves) if cves else line[:60]

            # Grab description from next lines
            desc_lines = []
            j = i + 1
            while j < min(i + 5, len(lines)):
                next_line = lines[j].strip()
                if next_line and not skip_patterns.match(next_line):
                    desc_lines.append(next_line)
                j += 1
            description = ' '.join(desc_lines)[:500]

            # Normalize title
            title = title[:120]
            if cves:
                title = title + ' (' + ', '.join(cves[:2]) + ')'

            # Deduplicate
            title_key = title.lower()[:40]
            if title_key not in seen_titles and len(title) > 5:
                seen_titles.add(title_key)
                findings.append({
                    'title': title,
                    'risk': detected_risk or 'Medium',
                    'description': description,
                    'cves': cves
                })

        i += 1

    # Cap at 50 findings per upload
    return findings[:50]
