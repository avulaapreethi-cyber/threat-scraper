import requests
from datetime import datetime, timedelta
from models import db, Threat

def fetch_and_store():
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=1)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 50
    }

    response = requests.get(url, params=params)
    data = response.json()

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})

        cve_id = cve.get("id")
        description = cve.get("descriptions", [{}])[0].get("value", "")

        metrics = cve.get("metrics", {})
        severity = "N/A"
        score = 0

        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        # Only store HIGH/CRITICAL
        if severity not in ["HIGH", "CRITICAL"]:
            continue

        # Avoid duplicates
        exists = Threat.query.filter_by(cve_id=cve_id).first()
        if not exists:
            threat = Threat(
                cve_id=cve_id,
                severity=severity,
                score=score,
                description=description[:200]
            )
            db.session.add(threat)

    db.session.commit()