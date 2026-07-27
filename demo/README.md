# Demo Data Scripts

These scripts generate synthetic demo data (fake findings, engagements,
vulnerability scans, users) for showcasing TracePatch — none of it is
required to run the actual application.

Run against a running container:

```bash
docker cp demo/generate_demo_pdf.py tracepatch:/opt/sectrack/app/
docker cp demo/seed_demo_findings.py tracepatch:/opt/sectrack/app/
docker cp demo/seed_demo_full.py tracepatch:/opt/sectrack/app/
docker compose exec tracepatch python3 app/generate_demo_pdf.py
docker compose exec tracepatch python3 app/seed_demo_findings.py
docker compose exec tracepatch python3 app/seed_demo_full.py
```

All data generated is entirely synthetic — fake hostnames, fake org names,
and real-but-unrelated public CVE numbers used for realism only.
