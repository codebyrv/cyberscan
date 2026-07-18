# # # import requests
# # # from django.conf import settings

# # # def submit_url(url):
# # #     headers = {
# # #         "x-apikey": settings.VT_API_KEY
# # #     }
    
# # #     print(headers)
    
    

# # #     response = requests.post(
# # #         "https://www.virustotal.com/api/v3/urls",
# # #         headers=headers,
# # #         data={"url": url}
# # #     )

# # #     return response.json()




# # import requests
# # from django.conf import settings

# # BASE_URL = "https://www.virustotal.com/api/v3"

import time
import os
import requests
from django.conf import settings

BASE_URL = "https://www.virustotal.com/api/v3"


def _get_api_key():
    # Prefer explicit environment variable, fallback to Django settings
    return os.getenv("VIRUSTOTAL_API_KEY") or getattr(settings, "VT_API_KEY", None)


def _get_headers():
    api_key = _get_api_key()
    if not api_key:
        return None, {
            "success": False,
            "error": "VirusTotal API key missing. Set VIRUSTOTAL_API_KEY or settings.VT_API_KEY."
        }

    return {"x-apikey": api_key}, None


def _request_with_retries(method, url, headers=None, retries=3, backoff_factor=1, **kwargs):
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.request(method, url, headers=headers, timeout=kwargs.pop("timeout", 15), **kwargs)
            return resp, None
        except requests.exceptions.SSLError as e:
            last_exc = e
            if attempt == retries:
                return None, e
            time.sleep(backoff_factor * (2 ** (attempt - 1)))
            continue
        except requests.exceptions.RequestException as e:
            last_exc = e
            if attempt == retries:
                return None, e
            time.sleep(backoff_factor * (2 ** (attempt - 1)))
            continue

    return None, last_exc

#     return response.json()


# # ==========================
# # 2. Get analysis report
# # ==========================
# def get_analysis(analysis_id):
#     response = requests.get(
#         f"{BASE_URL}/analyses/{analysis_id}",
#         headers=headers
#     )

#     return response.json()


# # ==========================
# # 3. WAIT until scan completes (IMPORTANT FIX)
# # ==========================
# def wait_for_analysis(analysis_id, timeout=30, interval=2):
#     """
#     Poll VirusTotal until analysis is completed.
#     """
#     start_time = time.time()

#     while True:
#         report = get_analysis(analysis_id)
#         attributes = report["data"]["attributes"]

#         status = attributes.get("status")

#         if status == "completed":
#             return report

#         # timeout safety
#         if time.time() - start_time > timeout:
#             return report

#         time.sleep(interval)



# import time
# import requests
# from django.conf import settings

# BASE_URL = "https://www.virustotal.com/api/v3"

# headers = {
#     "x-apikey": settings.VT_API_KEY
# }

# # =========================
# # 1. SUBMIT URL
# # =========================
# def submit_url(url):
#     response = requests.post(
#         f"{BASE_URL}/urls",
#         headers=headers,
#         data={"url": url}
#     )
#     return response.json()


# # =========================
# # 2. GET ANALYSIS
# # =========================
# def get_analysis(analysis_id):
#     response = requests.get(
#         f"{BASE_URL}/analyses/{analysis_id}",
#         headers=headers
#     )
#     return response.json()


# # =========================
# # 3. WAIT FUNCTION
# # =========================
# def wait_for_analysis(analysis_id, timeout=30, interval=2):

#     start_time = time.time()

#     while True:
#         report = get_analysis(analysis_id)

#         if not isinstance(report, dict):
#             return {"success": False, "error": "Invalid response"}

#         if "data" not in report:
#             return {"success": False, "error": "No data in response"}

#         attributes = report["data"].get("attributes", {})
#         status = attributes.get("status")

#         if status == "completed":
#             return report

#         if time.time() - start_time > timeout:
#             return {"success": False, "error": "Timeout"}

#         time.sleep(interval)



# =========================
# 1. SUBMIT URL (with header validation + retries)
# =========================
def submit_url(url):
    headers, err = _get_headers()
    if err:
        return err

    resp, exc = _request_with_retries(
        "POST", f"{BASE_URL}/urls", headers=headers, data={"url": url}, timeout=15
    )

    if exc:
        return {"success": False, "error": f"Network error contacting VirusTotal: {exc}. This may be a TLS/proxy issue."}

    try:
        payload = resp.json()
    except ValueError:
        return {"success": False, "error": "VirusTotal returned an invalid (non-JSON) response."}

    if resp.status_code not in (200, 201):
        error_msg = payload.get("error", {}).get(
            "message", f"VirusTotal error (status {resp.status_code})"
        )
        return {"success": False, "error": error_msg}

    if "data" not in payload:
        return {"success": False, "error": "VirusTotal response missing expected 'data' field."}

    return payload


# =========================
# 2. GET ANALYSIS (with header validation + retries)
# =========================
def get_analysis(analysis_id):
    headers, err = _get_headers()
    if err:
        return err

    resp, exc = _request_with_retries(
        "GET", f"{BASE_URL}/analyses/{analysis_id}", headers=headers, timeout=15
    )

    if exc:
        return {"success": False, "error": f"Network error contacting VirusTotal: {exc}."}

    try:
        payload = resp.json()
    except ValueError:
        return {"success": False, "error": "VirusTotal returned an invalid (non-JSON) response."}

    if resp.status_code not in (200, 201):
        error_msg = payload.get("error", {}).get(
            "message", f"VirusTotal error (status {resp.status_code})"
        )
        return {"success": False, "error": error_msg}

    return payload


# =========================
# 3. WAIT FUNCTION
# =========================
def wait_for_analysis(analysis_id, timeout=30, interval=2):

    start_time = time.time()

    while True:
        report = get_analysis(analysis_id)

        if not isinstance(report, dict):
            return {"success": False, "error": "Invalid response"}

        if report.get("success") is False:
            return report

        if "error" in report:
            return {"success": False, "error": report["error"].get("message", "VirusTotal error")}

        if "data" not in report:
            return {"success": False, "error": "No data in response"}

        attributes = report["data"].get("attributes", {})
        status = attributes.get("status")

        if status == "completed":
            return report

        if time.time() - start_time > timeout:
            return {"success": False, "error": "Timeout waiting for analysis to complete"}

        time.sleep(interval)