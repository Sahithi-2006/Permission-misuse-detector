import xml.etree.ElementTree as ET
import json
import os

ANDROID_NS = '{http://schemas.android.com/apk/res/android}'
DATASET_PATH = "permission_dataset.json"

if os.path.exists(DATASET_PATH):
    with open(DATASET_PATH, "r") as f:
        PERMISSION_DATASET = json.load(f)
else:
    PERMISSION_DATASET = {}


# ===============================
# Extract Permissions
# ===============================

def extract_permissions(manifest_path):
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    permissions = set()

    for elem in root.iter():
        if "uses-permission" in elem.tag:
            name = elem.get(f"{ANDROID_NS}name")
            if name:
                permissions.add(name)

    return permissions


# ===============================
# Detect System App
# ===============================

def is_system_app(manifest_path):
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    app = root.find("application")
    if app is not None:
        shared_user = root.get(f"{ANDROID_NS}sharedUserId")
        if shared_user:
            return True

    return False


# ===============================
# Intelligent Risk Scoring
# ===============================

def calculate_risk_score(permissions, is_system=False):

    score = 0
    detailed_report = []
    combos = []

    dangerous_count = 0
    signature_count = 0

    for perm in permissions:

        category = PERMISSION_DATASET.get(perm, "unknown")

        detailed_report.append((perm, category))

        if category == "normal":
            score += 0

        elif category == "dangerous":
            score += 2
            dangerous_count += 1.5

        elif category == "signature":
            signature_count += 3
            if not is_system:
                score += 4   # High risk if normal app requesting system permission

        elif category == "unknown":
            score += 0.3

    # Combo detection
    if "android.permission.READ_SMS" in permissions and \
       "android.permission.INTERNET" in permissions:
        combos.append("SMS + INTERNET (Possible Data Exfiltration)")
        score += 5

    if dangerous_count >= 5:
        combos.append("High number of dangerous permissions")
        score += 4

    if signature_count >= 3 and not is_system:
        combos.append("Non-system app requesting multiple system permissions")
        score += 6

    return score, detailed_report, combos


# ===============================
# Verdict
# ===============================

def verdict(score):

    if score >= 25:
        return "CRITICAL RISK"
    elif score >= 15:
        return "HIGH RISK"
    elif score >= 8:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"
