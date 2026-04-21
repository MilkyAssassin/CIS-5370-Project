import requests
import os
import json
from collections import defaultdict
import time
import zipfile
import tempfile
import json
from collections import defaultdict

MOBSF_URL = "http://localhost:8000"
API_KEY = "41032d28d94892ba199dac242e73c5343cc9fb5d30b4b56bb18f0a21fa6c29a9"

headers = {
    "Authorization": API_KEY
}

OUTPUT_DIR = "json_reports"

def upload_apk(file_path):
    url = f"{MOBSF_URL}/api/v1/upload"

    with open(file_path, "rb") as f:
        files = {
            "file": (os.path.basename(file_path), f, "application/vnd.android.package-archive")
        }

        r = requests.post(url, headers=headers, files=files)


    if r.status_code != 200:
        print("Upload failed response:", r.text)

    r.raise_for_status()

    result = r.json()

    return {
        "hash": result.get("hash") or result.get("md5"),
        "file_name": os.path.basename(file_path)
    }

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

def scan_apk(hash_value):
    url = f"{MOBSF_URL}/api/v1/scan"

    data = {
        "hash": hash_value
    }

    r = requests.post(url, headers=headers, data=data)

    if r.status_code != 200:
        print("Scan failed:", r.text)

    r.raise_for_status()

    return r.json()

def wait_for_report(hash_value, timeout=30):
    url = f"{MOBSF_URL}/api/v1/report_json"

    for _ in range(timeout):
        r = requests.post(url, headers=headers, data={"hash": hash_value})

        if r.status_code == 200:
            return r.json()

        time.sleep(2)

    raise Exception("Scan timed out for hash: " + hash_value)

def extract_apkm(apkm_path):
    temp_dir = tempfile.mkdtemp()

    with zipfile.ZipFile(apkm_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    # try base.apk first (most important)
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file == "base.apk":
                return os.path.join(root, file)

    # fallback
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith(".apk"):
                return os.path.join(root, file)

    return None

# ---------------------------
# Get all scanned apps
# ---------------------------
def get_scans():
    url = f"{MOBSF_URL}/api/v1/scans"

    r = requests.get(url, headers=headers)
    r.raise_for_status()

    return r.json().get("content", [])



# ---------------------------
# Get JSON report
# ---------------------------
def get_report(hash_value):
    url = f"{MOBSF_URL}/api/v1/report_json"

    data = {"hash": hash_value}

    r = requests.post(url, headers=headers, data=data)
    r.raise_for_status()

    return r.json()


# ---------------------------
# Save JSON
# ---------------------------
def save_json(app_name, report):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    safe_name = app_name.replace("/", "_")

    path = os.path.join(OUTPUT_DIR, f"{safe_name}.json")

    with open(path, "w") as f:
        json.dump(report, f, indent=4)


def download_pdf_report(hash_value, app_name):
    url = f"{MOBSF_URL}/api/v1/download_pdf"

    data = {
        "hash": hash_value
    }

    r = requests.post(url, headers=headers, data=data)

    if r.status_code != 200:
        print(f"PDF generation failed for {app_name}: {r.text}")
        return None

    os.makedirs("pdf_reports", exist_ok=True)

    safe_name = app_name.replace("/", "_")
    path = os.path.join("pdf_reports", f"{safe_name}.pdf")

    with open(path, "wb") as f:
        f.write(r.content)

    return path


def summarize(report):
    """
    Summarizes key security metrics from a MobSF JSON report.
    """
    counts = {"high": 0, "warning": 0, "info": 0}

    def add_from_summary(summary_obj):
        if summary_obj:
            for sev in ["high", "warning", "info"]:
                counts[sev] += summary_obj.get(sev, 0)

    # Extract existing summaries from different analysis modules
    add_from_summary(report.get("manifest_analysis", {}).get("manifest_summary"))
    add_from_summary(report.get("network_security", {}).get("network_summary"))
    add_from_summary(report.get("certificate_analysis", {}).get("certificate_summary"))

    # Process individual code analysis findings
    code_findings = report.get("code_analysis", {}).get("findings", [])
    for f in (code_findings or []):
        if isinstance(f, dict):
            severity = (f.get("severity") or "info").lower()
            counts[severity if severity in counts else "info"] += 1

    # Count vulnerabilities in shared libraries (NX, PIE, Stack Canary, etc.)
    binary_vulns = 0
    for lib in report.get("binary_analysis", []):
        for check in lib.values():
            if isinstance(check, dict) and check.get("severity") in ["high", "warning"]:
                binary_vulns += 1

    # Count permissions flagged as 'dangerous'
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

def main():
    apk_folder = "apks"
    
    # ---------------------------
    # 1. INITIALIZE DATA
    # ---------------------------
    # upload_folder, get_scans, scan_apk, wait_for_report, 
    # save_json, download_pdf_report are assumed to be defined.
    
    uploads = upload_folder(apk_folder)
    uploaded_hashes = {u["hash"] for u in uploads if u.get("hash")}
    existing_scans = get_scans()

    existing_hashes = set()
    combined = []

    for app in existing_scans:
        md5 = app.get("MD5")
        if md5:
            existing_hashes.add(md5)
            combined.append({"file_name": app.get("FILE_NAME"), "hash": md5})

    for app in uploads:
        if app.get("hash") and app["hash"] not in existing_hashes:
            combined.append(app)

    # ---------------------------
    # 2. PROCESS APPS
    # ---------------------------
    totals = defaultdict(int)
    per_app = {}
    seen_hashes = set()
    scores = []

    print(f"\nTotal unique apps to process: {len(combined)}\n")

    for app in combined:
        app_name = app["file_name"]
        hash_val = app["hash"]

        if not hash_val or hash_val in seen_hashes:
            continue
        seen_hashes.add(hash_val)

        print(f"[*] Processing: {app_name}")
        try:
            if hash_val in uploaded_hashes:
                scan_apk(hash_val)

            report = wait_for_report(hash_val)
            save_json(app_name, report)
            download_pdf_report(hash_val, app_name)

            summary = summarize(report)
            per_app[app_name] = summary
            scores.append(summary["security_score"])

            for k, v in summary.items():
                if isinstance(v, (int, float)):
                    totals[k] += v

        except Exception as e:
            print(f"[!] Error processing {app_name}: {e}")

    # ---------------------------
    # 3. FINAL SUMMARY OUTPUT
    # ---------------------------
    print("\n" + "="*30)
    print("      PER-APP ANALYSIS")
    print("="*30)
    for app, data in per_app.items():
        print(f"\n[+] {app} ({data['package_name']} v{data['version']})")
        print(f"    Score: {data['security_score']}/100")
        print(f"    Vulnerabilities: {data['high_findings']} High, {data['warning_findings']} Warning")
        print(f"    Privacy: {data['trackers']} Trackers, {data['dangerous_permissions']} Dangerous Perms")

    print("\n" + "="*30)
    print("      AGGREGATED TOTALS")
    print("="*30)
    for k, v in totals.items():
        if k != "security_score":
            print(f"{k.replace('_', ' ').title()}: {v}")
    
    if scores:
        avg_score = sum(scores) / len(scores)
        print(f"Average Security Score: {avg_score:.2f}/100")

if __name__ == "__main__":
    main()

# ---------------------------
# MAIN
# ---------------------------
def main():
    apk_folder = "apks"

    # ---------------------------
    # 1. UPLOAD NEW APKs FIRST
    # ---------------------------
    uploads = upload_folder(apk_folder)

    uploaded_hashes = set(u["hash"] for u in uploads if u.get("hash"))

    # ---------------------------
    # 2. EXISTING SCANS IN MOBSF
    # ---------------------------
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

    # ---------------------------
    # 3. ADD NEW UPLOADS (NO DUPLICATES)
    # ---------------------------
    for app in uploads:
        if not app.get("hash"):
            continue

        if app["hash"] not in existing_hashes:
            combined.append(app)
        else:
            print(f"Skipping already scanned: {app['file_name']}")

    # ---------------------------
    # 4. PROCESS EVERYTHING
    # ---------------------------
    totals = defaultdict(int)
    per_app = {}

    print(f"\nTotal apps to process: {len(combined)}\n")

    seen = set()

    for app in combined:
        app_name = app["file_name"]
        hash_value = app["hash"]

        if not hash_value:
            continue

        # 🔥 HARD DEDUPE BY HASH
        if hash_value in seen:
            print(f"Skipping duplicate hash: {app_name}")
            continue

        seen.add(hash_value)

        print(f"Processing {app_name}")

        try:
            # Only scan NEW uploads
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

    # ---------------------------
    # OUTPUT
    # ---------------------------
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