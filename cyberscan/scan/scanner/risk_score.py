# def calculate_risk(
#     url_features,
#     whois_info,
#     dns_info,
#     ssl_info,
#     html_info,
#     malicious,
#     suspicious
# ):

#     score = 0
#     reasons = []

#     # ==========================
#     # VirusTotal (Highest Priority)
#     # ==========================

#     if malicious >= 10:
#         score += 70
#         reasons.append(f"{malicious} antivirus engines flagged the URL as malicious.")

#     elif malicious >= 5:
#         score += 60
#         reasons.append(f"{malicious} antivirus engines detected malware/phishing.")

#     elif malicious > 0:
#         score += 40
#         reasons.append(f"{malicious} antivirus engines detected malicious activity.")

#     if suspicious > 0:
#         score += 15
#         reasons.append(f"{suspicious} engines marked the URL as suspicious.")

#     # ==========================
#     # URL Features
#     # ==========================

#     if not url_features["https"]:
#         score += 10
#         reasons.append("Website is not using HTTPS.")

#     if url_features["url_length"] > 75:
#         score += 10
#         reasons.append("Very long URL.")

#     if url_features["contains_ip"]:
#         score += 20
#         reasons.append("IP address used instead of domain.")

#     if url_features["contains_at"]:
#         score += 10
#         reasons.append("@ symbol detected in URL.")

#     if url_features["shortened_url"]:
#         score += 10
#         reasons.append("Shortened URL detected.")

#     if url_features["subdomain_count"] >= 3:
#         score += 10
#         reasons.append("Too many subdomains.")

#     if url_features["keyword_count"] > 0:
#         score += 10
#         reasons.append("Suspicious keywords found in URL.")

#     # ==========================
#     # WHOIS
#     # ==========================

#     if whois_info["success"]:

#         age = whois_info["domain_age_days"]

#         if age is not None:

#             if age < 30:
#                 score += 30
#                 reasons.append("Domain is less than 30 days old.")

#             elif age < 180:
#                 score += 15
#                 reasons.append("Domain is less than 6 months old.")

#     else:
#         score += 10
#         reasons.append("WHOIS information unavailable.")

#     # ==========================
#     # DNS
#     # ==========================

#     if dns_info["success"]:

#         if not dns_info["exists"]:
#             score += 20
#             reasons.append("DNS records not found.")

#     else:
#         score += 10
#         reasons.append("DNS lookup failed.")

#     # ==========================
#     # SSL
#     # ==========================

#     if ssl_info["success"]:

#         if ssl_info["expired"]:
#             score += 20
#             reasons.append("SSL certificate expired.")

#         if not ssl_info["https"]:
#             score += 10
#             reasons.append("HTTPS not enabled.")

#     else:
#         score += 15
#         reasons.append("SSL certificate unavailable.")

#     # ==========================
#     # HTML Analysis
#     # ==========================

#     if html_info["success"]:

#         if html_info["hidden_iframes"] > 0:
#             score += 10
#             reasons.append("Hidden iframe detected.")

#         if html_info["external_forms"] > 0:
#             score += 15
#             reasons.append("External form action detected.")

#         if html_info["meta_redirect"]:
#             score += 10
#             reasons.append("Meta refresh redirect detected.")

#         if html_info["password_inputs"] > 0:
#             score += 5
#             reasons.append("Password field found.")

#         if html_info["keyword_count"] >= 3:
#             score += 10
#             reasons.append("Suspicious webpage keywords detected.")

#     # ==========================
#     # Final Score
#     # ==========================

#     if score > 100:
#         score = 100

#     # ==========================
#     # Final Prediction
#     # ==========================

#     if malicious >= 5:

#         prediction = "PHISHING"

#         confidence = 99

#         color = "danger"

#     elif malicious > 0:

#         prediction = "LIKELY PHISHING"

#         confidence = 90

#         color = "danger"

#     elif score >= 70:

#         prediction = "PHISHING"

#         confidence = 90

#         color = "danger"

#     elif score >= 40:

#         prediction = "SUSPICIOUS"

#         confidence = 75

#         color = "warning"

#     else:

#         prediction = "SAFE"

#         confidence = 95

#         color = "success"

#     return {

#         "prediction": prediction,

#         "confidence": confidence,

#         "score": score,

#         "color": color,

#         "reasons": reasons
#     }




def calculate_risk(
    url_features,
    whois_info,
    dns_info,
    ssl_info,
    html_info,
    malicious,
    suspicious
):

    score = 0
    reasons = []

    # ==========================
    # VirusTotal (Highest Priority)
    # ==========================

    if malicious >= 10:
        score += 70
        reasons.append(f"{malicious} antivirus engines flagged the URL as malicious.")

    elif malicious >= 5:
        score += 60
        reasons.append(f"{malicious} antivirus engines detected malware/phishing.")

    elif malicious > 0:
        score += 40
        reasons.append(f"{malicious} antivirus engines detected malicious activity.")

    if suspicious > 0:
        score += 15
        reasons.append(f"{suspicious} engines marked the URL as suspicious.")

    # ==========================
    # URL Features (SAFE ACCESS)
    # ==========================

    if not url_features.get("https", False):
        score += 10
        reasons.append("Website is not using HTTPS.")

    if url_features.get("url_length", 0) > 75:
        score += 10
        reasons.append("Very long URL.")

    if url_features.get("contains_ip", False):
        score += 20
        reasons.append("IP address used instead of domain.")

    if url_features.get("contains_at", False):
        score += 10
        reasons.append("@ symbol detected in URL.")

    if url_features.get("shortened_url", False):
        score += 10
        reasons.append("Shortened URL detected.")

    if url_features.get("subdomain_count", 0) >= 3:
        score += 10
        reasons.append("Too many subdomains.")

    if url_features.get("keyword_count", 0) > 0:
        score += 10
        reasons.append("Suspicious keywords found in URL.")

    # ==========================
    # WHOIS
    # ==========================

    if whois_info.get("success"):

        age = whois_info.get("domain_age_days")

        if age is not None:
            if age < 30:
                score += 30
                reasons.append("Domain is less than 30 days old.")

            elif age < 180:
                score += 15
                reasons.append("Domain is less than 6 months old.")
    else:
        score += 10
        reasons.append("WHOIS information unavailable.")

    # ==========================
    # DNS
    # ==========================

    if dns_info.get("success"):

        if not dns_info.get("exists", True):
            score += 20
            reasons.append("DNS records not found.")

    else:
        score += 10
        reasons.append("DNS lookup failed.")

    # ==========================
    # SSL
    # ==========================

    if ssl_info.get("success"):

        if ssl_info.get("expired"):
            score += 25
            reasons.append("SSL certificate expired.")

        if not ssl_info.get("https"):
            score += 15
            reasons.append("HTTPS not enabled.")

        if ssl_info.get("issued_to") == "neverssl.com":
            score += 10
            reasons.append("Generic/unsafe certificate detected.")

    else:
        score += 20
        reasons.append("SSL certificate unavailable or invalid.")

    # ==========================
    # HTML Analysis
    # ==========================

    if html_info.get("success"):

        if html_info.get("hidden_iframes", 0) > 0:
            score += 10
            reasons.append("Hidden iframe detected.")

        if html_info.get("external_forms", 0) > 0:
            score += 15
            reasons.append("External form action detected.")

        if html_info.get("meta_redirect", False):
            score += 10
            reasons.append("Meta refresh redirect detected.")

        if html_info.get("password_inputs", 0) > 0:
            score += 5
            reasons.append("Password field found.")

        if html_info.get("keyword_count", 0) >= 3:
            score += 10
            reasons.append("Suspicious webpage keywords detected.")

    # 🔥 HTML FAILURE = RISK (IMPORTANT FIX)
    else:
        score += 20
        reasons.append("HTML analysis failed (possible bot protection, timeout, or cloaking).")

    # ==========================
    # FINAL SCORE LIMIT
    # ==========================

    if score > 100:
        score = 100

    # ==========================
    # FINAL PREDICTION ENGINE
    # ==========================

    if malicious >= 5:
        prediction = "PHISHING"
        confidence = 99
        color = "danger"

    elif malicious > 0:
        prediction = "LIKELY PHISHING"
        confidence = 90
        color = "danger"

    elif score >= 80:
        prediction = "PHISHING"
        confidence = 92
        color = "danger"

    elif score >= 50:
        prediction = "SUSPICIOUS"
        confidence = 80
        color = "warning"

    else:
        prediction = "SAFE"
        confidence = 95
        color = "success"

    return {
        "prediction": prediction,
        "confidence": confidence,
        "score": score,
        "color": color,
        "reasons": reasons
    }