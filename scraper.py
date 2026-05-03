import requests
import pandas as pd
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText

# ==============================
# CONFIGURATION
# ==============================
EMAIL_SENDER = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"   # NOT your normal password
EMAIL_RECEIVER = "receiver_email@gmail.com"

DAYS_BACK = 1
RESULTS_LIMIT = 50

# ==============================
# FETCH CVE DATA
# ==============================
end_date = datetime.utcnow()
start_date = end_date - timedelta(days=DAYS_BACK)

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

params = {
    "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
    "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
    "resultsPerPage": RESULTS_LIMIT
}

print(" Fetching latest CVEs...")

try:
    response = requests.get(url, params=params, timeout=15)
    response.raise_for_status()
    data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])
    results = []

    for item in vulnerabilities:
        cve = item.get("cve", {})

        cve_id = cve.get("id", "N/A")

        descriptions = cve.get("descriptions", [])
        description = descriptions[0]["value"] if descriptions else "N/A"
        description = description[:200] + "..." if len(description) > 200 else description

        metrics = cve.get("metrics", {})
        severity = "N/A"
        score = "N/A"

        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
            score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        results.append({
            "CVE_ID": cve_id,
            "Severity": severity,
            "Score": score,
            "Description": description
        })

    df = pd.DataFrame(results)

    # ==============================
    # FILTER CRITICAL ONLY
    # ==============================
    df = df[df["Severity"] == "CRITICAL"]

    # Save file
    df.to_csv("critical_threats.csv", index=False)

    print("\n CRITICAL THREATS:")
    print(df)

    # ==============================
    # SEND EMAIL IF FOUND
    # ==============================
    if not df.empty:
        print("\n Sending email alert...")

        message_body = "CRITICAL CVEs DETECTED:\n\n"

        for _, row in df.iterrows():
            message_body += f"{row['CVE_ID']} (Score: {row['Score']})\n{row['Description']}\n\n"

        msg = MIMEText(message_body)
        msg["Subject"] = "Critical CVE Alert"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        print(" Email sent successfully!")

    else:
        print("\n No critical threats found today.")

except Exception as e:
    print("❌ Error:", e)