import os
import time

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from zapv2 import ZAPv2

urllib3.disable_warnings(InsecureRequestWarning)

DEFAULT_ZAP_URLS = [
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://127.0.0.1:8081",
    "http://localhost:8081",
    "https://127.0.0.1:8080",
    "https://localhost:8080",
    "https://127.0.0.1:8081",
    "https://localhost:8081",
]
LAST_ZAP_CONNECTION_ERROR = None


def connect_to_zap(zap_url=None, api_key=None):
    global LAST_ZAP_CONNECTION_ERROR

    LAST_ZAP_CONNECTION_ERROR = None
    api_key = api_key or os.getenv("ZAP_API_KEY")
    if api_key == "paste-your-zap-api-key-here":
        api_key = None
    configured_zap_url = os.getenv("ZAP_PROXY_URL")
    candidate_urls = [zap_url] if zap_url else [configured_zap_url, *DEFAULT_ZAP_URLS]
    candidate_urls = list(dict.fromkeys(candidate for candidate in candidate_urls if candidate))
    errors = []

    for candidate in candidate_urls:
        for attempt in range(3):
            try:
                _check_zap_api(candidate, api_key)
                zap = ZAPv2(proxies={"http": candidate, "https": candidate}, apikey=api_key)
                if zap.core.version:
                    zap.proxy_url = candidate
                    return zap
            except Exception as exc:
                error_message = f"{candidate}: {exc}"
                errors.append(error_message)
                print(f"Retry {attempt + 1} of 3 for {candidate}: {exc}")
                time.sleep(2)
    LAST_ZAP_CONNECTION_ERROR = "; ".join(errors[-3:]) if errors else "No ZAP endpoints were configured."
    return None


def get_zap_version(zap):
    return zap.core.version


def get_last_zap_connection_error():
    return LAST_ZAP_CONNECTION_ERROR


def _check_zap_api(zap_url, api_key):
    params = {"apikey": api_key} if api_key else None
    response = requests.get(
        f"{zap_url.rstrip('/')}/JSON/core/view/version/",
        params=params,
        timeout=5,
        verify=False,
    )
    if response.status_code == 403:
        raise PermissionError(
            "403 Forbidden. ZAP is running, but the API key is missing, wrong, or not allowed."
        )
    response.raise_for_status()
