import json
import pandas as pd
import requests
from datetime import datetime, timedelta, timezone

#import software bill of materials
with open("sbom_current.json") as f:
    current = json.load(f)
with open("sbom_previous.json") as f:
    previous = json.load(f)


#convert to Pandas
def to_df(sbom):
    return pd.DataFrame([
        {
            "name": c["name"],
            "version": c["version"],
            "purl": c.get("purl"),
            "supplier": c.get("supplier", {}).get("name"),
        }
        for c in sbom["components"]
    ])

cur_df = to_df(current)
prev_df = to_df(previous)

#detect new dependencies
new_dep = cur_df[~cur_df["name"].isin(prev_df["name"])]

def enrich(package_name):
    now = datetime.now(timezone.utc)
    meta = {
        "found_on_registry": False,
        "package_age_days": 0,
        "has_vulnerabilities": False,
        "forces_source_build": False
    }
    
    pypi_url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        response = requests.get(pypi_url, timeout=5)
        
        # If it 404s, it might be an internal package OR a typosquatting attempt
        if response.status_code != 200:
            return meta 
            
        data = response.json()
        meta["found_on_registry"] = True

        releases = data.get("releases", {})
        earliest_date = now
        for version, uploads in releases.items():
            for upload in uploads:
                upload_time = datetime.fromisoformat(upload["upload_time"] + "+00:00")
                if upload_time < earliest_date:
                    earliest_date = upload_time
        
        meta["package_age_days"] = (now - earliest_date).days

        meta["has_vulnerabilities"] = len(data.get("vulnerabilities", [])) > 0

        latest_version = data.get("info", {}).get("version", "")
        latest_uploads = releases.get(latest_version, [])
        has_wheel = any(u["packagetype"] == "bdist_wheel" for u in latest_uploads)
        meta["forces_source_build"] = not has_wheel

        return meta
    
    except requests.RequestException:
        print(f"Warning: Failed to connect to PyPI for {package_name}")
        return meta

risks = []
for _, row in new_dep.iterrows():
    meta = enrich(row["name"])
    score = 0
    flags = []
    if not meta["found_on_registry"]:
        score += 6; flags.append("Private Package") #probably should remove if intending on working with trusted private packages
    if meta["package_age_days"] < 3:
        score += 5; flags.append("Brand New Package")
    elif meta["package_age_days"] < 14:
        score += 3; flags.append("New Package")
    elif meta["package_age_days"] < 30:
        score +=1; flags.append("Newer Package")
    if meta["forces_source_build"]:
        score += 3; flags.append("Forces Source Build")
    if meta["has_vulnerabilities"]:
        score +=6; flags.append("KNOWN VULNERABILITIES")
    risks.append({
        "package": row["name"],
        "version": row["version"],
        "risk_score": score,
        "reasons": flags,
    })

alerts = [r for r in risks if r["risk_score"] >= 6]
for a in alerts:
    print(f"ALERT: {a['package']}@{a['version']} score={a['risk_score']} reasons={a['reasons']}")