import os
import time
import json
import zipfile
import tempfile
import requests
from collections import defaultdict

# =========================
# CONFIGURATION
# =========================
MOBSF_URL = "http://localhost:8000" #Change port if port is different in MobSF docker
API_KEY = "41032d28d94892ba199dac242e73c5343cc9fb5d30b4b56bb18f0a21fa6c29a9" # To find API key go to your MobSF GUI and click API on top bar

HEADERS = {
    "Authorization": API_KEY
}

OUTPUT_DIR = "json_reports"


# =========================
# APK UPLOAD & EXTRACTION
# =========================
def upload_apk(file_path):
    url = f"{MOBSF_URL}/api/v1/upload"

    with open(file_path, "rb") as f:
        files = {
            "file": (os.path.basename(file_path), f, "application/vnd.android.package-archive")
        }

        r = requests.post(url, headers=HEADERS, files=files)

    if r.status_code != 200:
        print("Upload failed response:", r.text)

    r.raise_for_status()
    result = r.json()

    return {
        "hash": result.get("hash") or result.get("md5"),
        "file_name": os.path.basename(file_path)
    }


def extract_apkm(apkm_path):
    temp_dir = tempfile.mkdtemp()

    with zipfile.ZipFile(apkm_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith(".apk"):
                return os.path.join(root, file)

    return None


def upload_folder(folder_path):
    uploads = []

    for file in os.listdir(folder_path):
        full_path = os.path.join(folder_path, file)
        target_path = None

        if file.endswith(".apk"):
            target_path = full_path

        elif file.endswith(".apkm"):
            print(f"Extracting APKM: {file}")
            target_path = extract_apkm(full_path)

            if not target_path:
                print(f"Failed to extract: {file}")
                continue
        else:
            continue

        print(f"Uploading {file}...")

        try:
            result = upload_apk(target_path)
            uploads.append(result)
        except Exception as e:
            print(f"Failed to upload {file}: {e}")

    return uploads


# =========================
# SCANNING & REPORTING
# =========================
def scan_apk(hash_value):
    url = f"{MOBSF_URL}/api/v1/scan"

    data = {"hash": hash_value}
    r = requests.post(url, headers=HEADERS, data=data)

    if r.status_code != 200:
        print("Scan failed:", r.text)

    r.raise_for_status()
    return r.json()


def wait_for_report(hash_value, timeout=30):
    url = f"{MOBSF_URL}/api/v1/report_json"

    for _ in range(timeout):
        r = requests.post(url, headers=HEADERS, data={"hash": hash_value})

        if r.status_code == 200:
            return r.json()

        time.sleep(2)

    raise Exception("Scan timed out for hash: " + hash_value)


def get_scans():
    url = f"{MOBSF_URL}/api/v1/scans"

    r = requests.get(url, headers=HEADERS)
    r.raise_for_status()

    return r.json().get("content", [])


def get_report(hash_value):
    url = f"{MOBSF_URL}/api/v1/report_json"

    r = requests.post(url, headers=HEADERS, data={"hash": hash_value})
    r.raise_for_status()

    return r.json()


# =========================
# OUTPUT HANDLING
# =========================
def save_json(app_name, report):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    safe_name = app_name.replace("/", "_")
    path = os.path.join(OUTPUT_DIR, f"{safe_name}.json")

    with open(path, "w") as f:
        json.dump(report, f, indent=4)


def download_pdf_report(hash_value, app_name):
    url = f"{MOBSF_URL}/api/v1/download_pdf"

    r = requests.post(url, headers=HEADERS, data={"hash": hash_value})

    if r.status_code != 200:
        print(f"PDF generation failed for {app_name}: {r.text}")
        return None

    os.makedirs("pdf_reports", exist_ok=True)

    safe_name = app_name.replace("/", "_")
    path = os.path.join("pdf_reports", f"{safe_name}.pdf")

    with open(path, "wb") as f:
        f.write(r.content)

    return path


# =========================
# REPORT ANALYSIS
# =========================
def summarize(report):
    counts = {"high": 0, "warning": 0, "info": 0}

    def add_from_summary(summary_obj):
        if summary_obj:
            for sev in ["high", "warning", "info"]:
                counts[sev] += summary_obj.get(sev, 0)

    add_from_summary(report.get("manifest_analysis", {}).get("manifest_summary"))
    add_from_summary(report.get("network_security", {}).get("network_summary"))
    add_from_summary(report.get("certificate_analysis", {}).get("certificate_summary"))

    code_findings = report.get("code_analysis", {}).get("findings", [])
    for f in (code_findings or []):
        if isinstance(f, dict):
            severity = (f.get("severity") or "info").lower()
            counts[severity if severity in counts else "info"] += 1

    binary_vulns = 0
    for lib in report.get("binary_analysis", []):
        for check in lib.values():
            if isinstance(check, dict) and check.get("severity") in ["high", "warning"]:
                binary_vulns += 1

    permissions = report.get("permissions", {})
    dangerous_perms = sum(1 for p in permissions.values() if p.get("status") == "dangerous")

    return {
        "high_findings": counts["high"],
        "warning_findings": counts["warning"],
        "info_findings": counts["info"],
        "binary_vulnerabilities": binary_vulns,
        "dangerous_permissions": dangerous_perms,
        "malware_perms_count": report.get("malware_permissions", {}).get("total_malware_permissions", 0),
        "trackers": report.get("trackers", 0),
        "total_trackers": report.get("total_trackers", 0),
        "security_score": report.get("security_score", 0),
        "package_name": report.get("package_name", "N/A"),
        "version": report.get("version_name", "N/A")
    }


# =========================
# MAIN PIPELINE
# =========================
def main():
    apk_folder = "apks"

    uploads = upload_folder(apk_folder)
    uploaded_hashes = set(u["hash"] for u in uploads if u.get("hash"))

    existing_scans = get_scans()

    existing_hashes = set()
    combined = []

    for app in existing_scans:
        md5 = app.get("MD5")
        if md5:
            existing_hashes.add(md5)
            combined.append({
                "file_name": app.get("FILE_NAME"),
                "hash": md5
            })

    for app in uploads:
        if not app.get("hash"):
            continue

        if app["hash"] not in existing_hashes:
            combined.append(app)
        else:
            print(f"Skipping already scanned: {app['file_name']}")

    totals = defaultdict(int)
    per_app = {}

    print(f"\nTotal apps to process: {len(combined)}\n")

    seen = set()

    for app in combined:
        app_name = app["file_name"]
        hash_value = app["hash"]

        if not hash_value:
            continue

        if hash_value in seen:
            print(f"Skipping duplicate hash: {app_name}")
            continue

        seen.add(hash_value)

        print(f"Processing {app_name}")

        try:
            if hash_value in uploaded_hashes:
                scan_apk(hash_value)

            report = wait_for_report(hash_value)

            save_json(app_name, report)

            pdf_path = download_pdf_report(hash_value, app_name)
            if pdf_path:
                print(f"PDF saved: {pdf_path}")

            summary = summarize(report)
            per_app[app_name] = summary

            for k, v in summary.items():
                totals[k] += v

        except Exception as e:
            print(f"Failed on {app_name}: {e}")

    print("\n=== PER APP ===")
    for app, data in per_app.items():
        print(f"\n{app}")
        for k, v in data.items():
            print(f"  {k}: {v}")

    print("\n=== TOTALS ===")
    for k, v in totals.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()