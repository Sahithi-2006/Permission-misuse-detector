import xml.etree.ElementTree as ET
import sys
import os

# Define the Android namespace constant for better readability
ANDROID_NS = '{http://schemas.android.com/apk/res/android}'

HIGH_RISK_PERMISSIONS = {
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.INTERACT_ACROSS_USERS_FULL",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.GET_TASKS"
}

def calculate_risk_score(permissions):
    """Calculates the risk score based on the list of permissions."""
    risk_score = 0
    for p in permissions:
        if p in HIGH_RISK_PERMISSIONS:
            risk_score += 3
        elif "LOCATION" in p or "FOREGROUND" in p:
            risk_score += 2
        else:
            risk_score += 1
    return risk_score

def extract_permissions(path):
    # 1. Check if file exists
    if not os.path.exists(path):
        print(f"Error: The file '{path}' was not found.")
        return []

    try:
        tree = ET.parse(path)
        root = tree.getroot()

        permissions = []
        for perm in root.findall("uses-permission"):
            # 2. Use .get() for safer access
            name = perm.get(f"{ANDROID_NS}name")
            if name:
                permissions.append(name)
        
        return permissions

    except ET.ParseError as e:
        print(f"Error: Failed to parse XML file. {e}")
        return []
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []

if __name__ == "__main__":
    # 3. Allow passing file path as argument
    manifest_path = "calculator/AndroidManifest.xml"
    if len(sys.argv) > 1:
        manifest_path = sys.argv[1]

    perms = extract_permissions(manifest_path)

    if perms:
        print(f"Permissions Found ({len(perms)}):")
        for p in perms:
            print(f"Perm: {p}")

        risk_score = calculate_risk_score(perms)
        print(f"\nRisk Score: {risk_score}")

        if risk_score > 10:
            print("🚨 HIGH RISK APPLICATION")
        elif risk_score > 5:
            print("⚠ MEDIUM RISK APPLICATION")
        else:
            print("LOW RISK")