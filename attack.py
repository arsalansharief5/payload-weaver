import time


SCAN_PROFILES = {
    "quick": {"active_scan": False, "alert_limit": 50},
    "regular": {"active_scan": True, "alert_limit": 100},
    "deep": {"active_scan": True, "alert_limit": 250},
}


def attack_website(zap, target_url, scan_type, attack_type="all"):
    profile = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["regular"])

    _wait_for_passive_scan(zap)

    if profile["active_scan"]:
        scan_id = zap.ascan.scan(target_url, recurse=True, inscopeonly=False)
        while int(zap.ascan.status(scan_id)) < 100:
            time.sleep(2)

    _wait_for_passive_scan(zap)
    alerts = zap.core.alerts(baseurl=target_url, start=0, count=profile["alert_limit"])
    return _normalize_alerts(alerts)


def _wait_for_passive_scan(zap, max_wait=120):
    waited = 0
    while waited < max_wait:
        try:
            if int(zap.pscan.records_to_scan) == 0:
                return
        except Exception:
            return
        time.sleep(1)
        waited += 1


def _normalize_alerts(alerts):
    vulnerabilities = []
    seen = set()

    for alert in alerts:
        fingerprint = (
            alert.get("pluginId"),
            alert.get("name"),
            alert.get("url"),
            alert.get("param"),
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)

        vulnerabilities.append(
            {
                "name": alert.get("name", "Unnamed finding"),
                "risk": alert.get("risk", "Informational"),
                "description": alert.get("description", "No description provided by ZAP."),
                "solution": alert.get("solution", "No remediation guidance provided by ZAP."),
                "url": alert.get("url", ""),
                "affected_url": alert.get("url", ""),
                "parameter": alert.get("param", ""),
                "evidence": alert.get("evidence", ""),
                "reference": alert.get("reference", ""),
                "attack": alert.get("attack", ""),
            }
        )

    vulnerabilities.sort(
        key=lambda item: {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}.get(item["risk"], 4)
    )
    return vulnerabilities
