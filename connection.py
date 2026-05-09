import os
import time

import urllib3
from urllib3.exceptions import InsecureRequestWarning
from zapv2 import ZAPv2

urllib3.disable_warnings(InsecureRequestWarning)

DEFAULT_ZAP_API_KEY = os.getenv("ZAP_API_KEY")
DEFAULT_ZAP_URLS = [
    os.getenv("ZAP_PROXY_URL"),
    "http://127.0.0.1:8080",
    "http://localhost:8080",
]


def connect_to_zap(zap_url=None, api_key=None):
    api_key = api_key or DEFAULT_ZAP_API_KEY
    candidate_urls = [zap_url] if zap_url else DEFAULT_ZAP_URLS
    candidate_urls = [candidate for candidate in candidate_urls if candidate]

    for candidate in candidate_urls:
        for attempt in range(3):
            try:
                zap = ZAPv2(proxies={"http": candidate, "https": candidate}, apikey=api_key)
                if zap.core.version:
                    zap.proxy_url = candidate
                    return zap
            except Exception:
                print(f"Retry {attempt + 1} of 3 for {candidate}...")
                time.sleep(2)
    return None


def get_zap_version(zap):
    return zap.core.version
