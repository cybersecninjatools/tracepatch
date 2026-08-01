# Demo Data Scripts

These scripts generate synthetic demo data (fake findings, engagements,
vulnerability scans, users) for showcasing TracePatch — none of it is
required to run the actual application. All records they create are flagged
`is_demo=1` and behave per the "Demo data" section of [SETUP.md](../SETUP.md):
protected from deletion, hidden automatically the moment you create real
(non-demo) data, and toggleable via the "Show demo data" setting.

They're baked into every image (`Dockerfile` copies `demo/`), so there's no
need to `docker cp` anything in first — just run them against a running
container:

```bash
docker compose exec tracepatch python3 demo/seed_demo_findings.py
docker compose exec tracepatch python3 demo/seed_demo_full.py
```

`seed_demo_findings.py` creates the primary demo engagement and its findings;
`seed_demo_full.py` adds a second engagement, more findings, vulnerability
scan data, two extra demo user accounts (`achen` / `jreyes`, password
`DemoPass123!`), and the `demo_data_visible` app setting. Both are safe to
re-run — they check for existing rows by name before inserting settings/users,
though re-running will add duplicate findings/engagements since those aren't
deduplicated.

## Optional: demoing the PDF upload/parsing feature

`generate_demo_pdf.py` renders a synthetic pen test report PDF you can upload
through the app's UI to demo the PDF-parsing import flow. It's unrelated to
the SQL-based seeding above (its data just happens to describe the same fake
findings) and needs `reportlab`, which isn't installed in the image by
default:

```bash
docker compose exec tracepatch pip install reportlab
docker compose exec tracepatch python3 demo/generate_demo_pdf.py
```

This writes `demo_pentest_report.pdf` inside the container — copy it out with
`docker cp` and upload it via the app's Import page. The PDF parser doesn't
extract titles perfectly for every finding; `fix_demo_titles.py` is a
one-time cleanup script for the titles that come out wrong if you go this
route.

All data generated is entirely synthetic — fake hostnames, fake org names,
and real-but-unrelated public CVE numbers used for realism only.
