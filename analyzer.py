import requests
import os
import json
from collections import defaultdict
import time
import zipfile
import tempfile

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

    # Debug help (VERY useful for 400 errors)
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


def summarize(report):
    counts = {
        "high": 0,
        "warning": 0,
        "info": 0
    }

    def process_findings(findings):
        for f in findings or []:
            if isinstance(f, dict):
                severity = (f.get("severity") or "").lower()
                if severity in counts:
                    counts[severity] += 1
                else:
                    counts["info"] += 1  # fallback

    # -------------------------
    # CODE ANALYSIS
    # -------------------------
    code = report.get("code_analysis", {})
    process_findings(code.get("findings"))

    # -------------------------
    # MANIFEST ANALYSIS
    # -------------------------
    manifest = report.get("manifest_analysis", {})
    process_findings(manifest.get("manifest_findings"))

    return counts

# ---------------------------
# MAIN
# ---------------------------
def main():
    apk_folder = "apks"

    # ---------------------------
    # 1. EXISTING SCANS IN MOBSF
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
    # 2. UPLOAD NEW APKs
    # ---------------------------
    uploads = upload_folder(apk_folder)

    for app in uploads:
        if app["hash"] not in existing_hashes:
            combined.append(app)
        else:
            print(f"Skipping already scanned: {app['file_name']}")

    # ---------------------------
    # 3. PROCESS EVERYTHING
    # ---------------------------
    totals = defaultdict(int)
    per_app = {}

    print(f"\nTotal apps to process: {len(combined)}\n")

    for app in combined:
        app_name = app["file_name"]
        hash_value = app["hash"]

        if not hash_value:
            continue

        print(f"Processing {app_name}")

        try:
            # Only scan if NOT already scanned
            if app_name in [u["file_name"] for u in uploads]:
                scan_apk(hash_value)

            report = wait_for_report(hash_value)

            save_json(app_name, report)

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