
# import time
# from datetime import datetime

# from django.shortcuts import render

# from .forms import URLForm
# from .services import submit_url, get_analysis


# def home(request):

#     form = URLForm()

#     context = {
#         "form": form
#     }

#     if request.method == "POST":

#         form = URLForm(request.POST)

#         if form.is_valid():

#             url = form.cleaned_data["url"]

#             # Submit URL to VirusTotal
#             submit_response = submit_url(url)

#             analysis_id = submit_response["data"]["id"]

#             # Wait for VirusTotal
#             time.sleep(3)

#             # Get report
#             report = get_analysis(analysis_id)

#             attributes = report["data"]["attributes"]

#             stats = attributes["stats"]

#             harmless = stats.get("harmless", 0)
#             malicious = stats.get("malicious", 0)
#             suspicious = stats.get("suspicious", 0)
#             undetected = stats.get("undetected", 0)

#             total = harmless + malicious + suspicious + undetected

#             # Verdict
#             if malicious > 0:
#                 verdict = "Malicious"
#                 verdict_color = "danger"

#             elif suspicious > 0:
#                 verdict = "Suspicious"
#                 verdict_color = "warning"

#             else:
#                 verdict = "Safe"
#                 verdict_color = "success"

#             # Scan time
#             scan_time = ""

#             if "date" in attributes:

#                 scan_time = datetime.fromtimestamp(
#                     attributes["date"]
#                 ).strftime("%d %b %Y %I:%M %p")

#             # Engine Results
#             engines = []

#             print("\n========== VirusTotal Engines ==========\n")

#             for name, engine in attributes["results"].items():

#                 category = engine.get("category", "unknown")

#                 print(name, "->", category)

#                 engines.append({

#                     "name": name,

#                     "category": category

#                 })

#             # Sort engines
#             priority = {

#                 "malicious": 0,

#                 "suspicious": 1,

#                 "harmless": 2,

#                 "undetected": 3,

#                 "timeout": 4,

#                 "unknown": 5

#             }

#             engines.sort(
#                 key=lambda x: priority.get(x["category"], 5)
#             )

#             context = {

#                 "form": form,

#                 "url": url,

#                 "analysis_id": analysis_id,

#                 "status": attributes["status"],

#                 "verdict": verdict,

#                 "verdict_color": verdict_color,

#                 "harmless": harmless,

#                 "malicious": malicious,

#                 "suspicious": suspicious,

#                 "undetected": undetected,

#                 "ratio": f"{malicious}/{total}",

#                 "scan_time": scan_time,

#                 # Change [:50] to [:20] or remove it if you want all
#                 "engines": engines[:50]

#             }

#     return render(request, "home.html", context)




# import time
# from datetime import datetime

# from django.shortcuts import render

# from .forms import URLForm
# from .services import submit_url, get_analysis

# # NEW MODULES
# from .feature_extractor import extract_features
# from .whois_checker import get_whois_info
# from .dns_checker import get_dns_info
# from .ssl_checker import get_ssl_info
# from .html_analyzer import analyze_html
# from .risk_score import calculate_risk


# def home(request):

#     form = URLForm()

#     context = {
#         "form": form
#     }

#     if request.method == "POST":

#         form = URLForm(request.POST)

#         if form.is_valid():

#             url = form.cleaned_data["url"]

#             # ==============================
#             # 1. VIRUSTOTAL SCAN
#             # ==============================
#             submit_response = submit_url(url)
#             analysis_id = submit_response["data"]["id"]

#             time.sleep(3)  # simple wait (later replace with polling)

#             report = get_analysis(analysis_id)
#             attributes = report["data"]["attributes"]
#             stats = attributes["stats"]

#             harmless = stats.get("harmless", 0)
#             malicious = stats.get("malicious", 0)
#             suspicious = stats.get("suspicious", 0)
#             undetected = stats.get("undetected", 0)

#             total = harmless + malicious + suspicious + undetected

#             # Verdict
#             if malicious > 0:
#                 verdict = "Malicious"
#                 verdict_color = "danger"

#             elif suspicious > 0:
#                 verdict = "Suspicious"
#                 verdict_color = "warning"

#             else:
#                 verdict = "Safe"
#                 verdict_color = "success"

#             # Scan time
#             scan_time = ""
#             if "date" in attributes:
#                 scan_time = datetime.fromtimestamp(
#                     attributes["date"]
#                 ).strftime("%d %b %Y %I:%M %p")

#             # Engine Results
#             engines = []

#             for name, engine in attributes["results"].items():
#                 engines.append({
#                     "name": name,
#                     "category": engine.get("category", "unknown")
#                 })

#             priority = {
#                 "malicious": 0,
#                 "suspicious": 1,
#                 "harmless": 2,
#                 "undetected": 3,
#                 "timeout": 4,
#                 "unknown": 5
#             }

#             engines.sort(
#                 key=lambda x: priority.get(x["category"], 5)
#             )

#             # ==============================
#             # 2. EXTRA SECURITY ANALYSIS
#             # ==============================
#             url_features = extract_features(url)
#             whois_info = get_whois_info(url)
#             dns_info = get_dns_info(url)
#             ssl_info = get_ssl_info(url)
#             html_info = analyze_html(url)

#             # ==============================
#             # 3. RISK SCORE ENGINE
#             # ==============================
#             risk = calculate_risk(
#                 url_features,
#                 whois_info,
#                 dns_info,
#                 ssl_info,
#                 html_info,
#                 malicious,
#                 suspicious
#             )

#             # ==============================
#             # FINAL CONTEXT
#             # ==============================
#             context = {
#                 "form": form,

#                 # URL + VT
#                 "url": url,
#                 "analysis_id": analysis_id,
#                 "status": attributes["status"],
#                 "verdict": verdict,
#                 "verdict_color": verdict_color,
#                 "harmless": harmless,
#                 "malicious": malicious,
#                 "suspicious": suspicious,
#                 "undetected": undetected,
#                 "ratio": f"{malicious}/{total}",
#                 "scan_time": scan_time,
#                 "engines": engines[:50],

#                 # NEW MODULE OUTPUTS
#                 "url_features": url_features,
#                 "whois_info": whois_info,
#                 "dns_info": dns_info,
#                 "ssl_info": ssl_info,
#                 "html_info": html_info,

#                 # FINAL AI RISK ENGINE
#                 "risk": risk,
#             }

#     return render(request, "home.html", context)



# from datetime import datetime

# from django.shortcuts import render

# from .forms import URLForm
# from .services import submit_url, wait_for_analysis

# # NEW MODULES
# from .feature_extractor import extract_features
# from .whois_checker import get_whois_info
# from .dns_checker import get_dns_info
# from .ssl_checker import get_ssl_info
# from .html_analyzer import analyze_html
# from .risk_score import calculate_risk


# def home(request):

#     form = URLForm()

#     context = {
#         "form": form
#     }

#     if request.method == "POST":

#         form = URLForm(request.POST)

#         if form.is_valid():

#             url = form.cleaned_data["url"]

#             # ==============================
#             # 1. VIRUSTOTAL SCAN
#             # ==============================

#             submit_response = submit_url(url)
#             analysis_id = submit_response["data"]["id"]

#             report = wait_for_analysis(analysis_id)

#             if report.get("success") is False:
#                 context["error"] = report["error"]
#                 return render(request, "home.html", context)

#             attributes = report["data"]["attributes"]
#             stats = attributes["stats"]

#             harmless = stats.get("harmless", 0)
#             malicious = stats.get("malicious", 0)
#             suspicious = stats.get("suspicious", 0)
#             undetected = stats.get("undetected", 0)

#             total = harmless + malicious + suspicious + undetected

#             # ==============================
#             # VirusTotal Verdict
#             # ==============================

#             if malicious > 0:
#                 verdict = "Malicious"
#                 verdict_color = "danger"

#             elif suspicious > 0:
#                 verdict = "Suspicious"
#                 verdict_color = "warning"

#             else:
#                 verdict = "Safe"
#                 verdict_color = "success"

#             # ==============================
#             # Scan Time
#             # ==============================

#             scan_time = ""

#             if "date" in attributes:
#                 scan_time = datetime.fromtimestamp(
#                     attributes["date"]
#                 ).strftime("%d %b %Y %I:%M %p")

#             # ==============================
#             # Engine Results
#             # ==============================

#             engines = []

#             for name, engine in attributes.get("results", {}).items():

#                 engines.append({
#                     "name": name,
#                     "category": engine.get("category", "unknown")
#                 })

#             priority = {
#                 "malicious": 0,
#                 "suspicious": 1,
#                 "harmless": 2,
#                 "undetected": 3,
#                 "timeout": 4,
#                 "unknown": 5
#             }

#             engines.sort(
#                 key=lambda x: priority.get(x["category"], 5)
#             )

#             # ==============================
#             # 2. EXTRA SECURITY ANALYSIS
#             # ==============================

#             url_features = extract_features(url)
#             whois_info = get_whois_info(url)
#             dns_info = get_dns_info(url)
#             ssl_info = get_ssl_info(url)
#             html_info = analyze_html(url)

#             # ==============================
#             # 3. AI RISK ENGINE
#             # ==============================

#             risk = calculate_risk(
#                 url_features,
#                 whois_info,
#                 dns_info,
#                 ssl_info,
#                 html_info,
#                 malicious,
#                 suspicious
#             )

#             # ==============================
#             # 4. OVERALL ASSESSMENT
#             # ==============================

#             if malicious > 0:

#                 overall = {
#                     "label": "Critical Risk",
#                     "color": "danger",
#                     "icon": "🔴"
#                 }

#             elif suspicious > 0:

#                 overall = {
#                     "label": "High Risk",
#                     "color": "warning",
#                     "icon": "🟠"
#                 }

#             else:

#                 if risk["prediction"] == "SAFE":

#                     overall = {
#                         "label": "Low Risk",
#                         "color": "success",
#                         "icon": "🟢"
#                     }

#                 elif risk["prediction"] == "SUSPICIOUS":

#                     overall = {
#                         "label": "Medium Risk",
#                         "color": "warning",
#                         "icon": "🟡"
#                     }

#                 else:

#                     overall = {
#                         "label": "High Risk",
#                         "color": "danger",
#                         "icon": "🟠"
#                     }
                    
#             ml_prediction = risk["prediction"]

#             if malicious > 0:
#                 vt_prediction = "❌ Malicious"
#             elif suspicious > 0:
#                 vt_prediction = "⚠️ Suspicious"
#             else:
#                 vt_prediction = "✅ No detections"

#             overall_verdict = f'{overall["icon"]} {overall["label"]}'        
                                
                    

#             # ==============================
#             # FINAL CONTEXT
#             # ==============================

#             context = {

#                 "form": form,

#                 # VirusTotal
#                 "url": url,
#                 "analysis_id": analysis_id,
#                 "status": attributes.get("status"),
#                 "verdict": verdict,
#                 "verdict_color": verdict_color,
#                 "harmless": harmless,
#                 "malicious": malicious,
#                 "suspicious": suspicious,
#                 "undetected": undetected,
#                 "ratio": f"{malicious}/{total}",
#                 "scan_time": scan_time,
#                 "engines": engines[:50],

#                 # Extra Analysis
#                 "url_features": url_features,
#                 "whois_info": whois_info,
#                 "dns_info": dns_info,
#                 "ssl_info": ssl_info,
#                 "html_info": html_info,

#                 # AI Risk Engine
#                 "risk": risk,
#                 "ml_prediction": ml_prediction,
#                 "vt_prediction": vt_prediction,
#                 "overall_verdict": overall_verdict,
#                 # Overall Result
#                 "overall": overall,
#             }


#     from pprint import pprint

#     # Print all context variables
#     print("\n========== CONTEXT ==========")
#     pprint(context)
#     print("=============================\n")

#     return render(request, "home.html", context)

#     print(context)

        
        
from datetime import datetime

from django.shortcuts import render

from .forms import URLForm
from .services import submit_url, wait_for_analysis

# NEW MODULES
from .feature_extractor import extract_features
from .whois_checker import get_whois_info
from .dns_checker import get_dns_info
from .ssl_checker import get_ssl_info
from .html_analyzer import analyze_html
from .risk_score import calculate_risk


def home(request):

    form = URLForm()

    context = {
        "form": form
    }

    if request.method == "POST":

        form = URLForm(request.POST)

        if form.is_valid():

            url = form.cleaned_data["url"]

            # ==============================
            # 1. VIRUSTOTAL SCAN
            # ==============================

            submit_response = submit_url(url)

            if submit_response.get("success") is False or "data" not in submit_response:
                context["error"] = submit_response.get(
                    "error", "Failed to submit URL to VirusTotal."
                )
                return render(request, "home.html", context)

            analysis_id = submit_response["data"]["id"]

            report = wait_for_analysis(analysis_id)

            if report.get("success") is False:
                context["error"] = report["error"]
                return render(request, "home.html", context)

            attributes = report["data"]["attributes"]
            stats = attributes["stats"]

            harmless = stats.get("harmless", 0)
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)

            total = harmless + malicious + suspicious + undetected

            # ==============================
            # VirusTotal Verdict
            # ==============================

            if malicious > 0:
                verdict = "Malicious"
                verdict_color = "danger"

            elif suspicious > 0:
                verdict = "Suspicious"
                verdict_color = "warning"

            else:
                verdict = "Safe"
                verdict_color = "success"

            # ==============================
            # Scan Time
            # ==============================

            scan_time = ""

            if "date" in attributes:
                scan_time = datetime.fromtimestamp(
                    attributes["date"]
                ).strftime("%d %b %Y %I:%M %p")

            # ==============================
            # Engine Results
            # ==============================

            engines = []

            for name, engine in attributes.get("results", {}).items():

                engines.append({
                    "name": name,
                    "category": engine.get("category", "unknown")
                })

            priority = {
                "malicious": 0,
                "suspicious": 1,
                "harmless": 2,
                "undetected": 3,
                "timeout": 4,
                "unknown": 5
            }

            engines.sort(
                key=lambda x: priority.get(x["category"], 5)
            )

            # ==============================
            # 2. EXTRA SECURITY ANALYSIS
            # ==============================

            url_features = extract_features(url)
            whois_info = get_whois_info(url)
            dns_info = get_dns_info(url)
            ssl_info = get_ssl_info(url)
            html_info = analyze_html(url)

            # ==============================
            # 3. AI RISK ENGINE
            # ==============================

            risk = calculate_risk(
                url_features,
                whois_info,
                dns_info,
                ssl_info,
                html_info,
                malicious,
                suspicious
            )

            # ==============================
            # 4. OVERALL ASSESSMENT
            # ==============================

            if malicious > 0:

                overall = {
                    "label": "Critical Risk",
                    "color": "danger",
                    "icon": "🔴"
                }

            elif suspicious > 0:

                overall = {
                    "label": "High Risk",
                    "color": "warning",
                    "icon": "🟠"
                }

            else:

                if risk["prediction"] == "SAFE":

                    overall = {
                        "label": "Low Risk",
                        "color": "success",
                        "icon": "🟢"
                    }

                elif risk["prediction"] == "SUSPICIOUS":

                    overall = {
                        "label": "Medium Risk",
                        "color": "warning",
                        "icon": "🟡"
                    }

                else:

                    overall = {
                        "label": "High Risk",
                        "color": "danger",
                        "icon": "🟠"
                    }

            ml_prediction = risk["prediction"]

            if malicious > 0:
                vt_prediction = "❌ Malicious"
            elif suspicious > 0:
                vt_prediction = "⚠️ Suspicious"
            else:
                vt_prediction = "✅ No detections"

            overall_verdict = f'{overall["icon"]} {overall["label"]}'

            # ==============================
            # FINAL CONTEXT
            # ==============================

            context = {

                "form": form,

                # VirusTotal
                "url": url,
                "analysis_id": analysis_id,
                "status": attributes.get("status"),
                "verdict": verdict,
                "verdict_color": verdict_color,
                "harmless": harmless,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "ratio": f"{malicious}/{total}",
                "scan_time": scan_time,
                "engines": engines[:50],

                # Extra Analysis
                "url_features": url_features,
                "whois_info": whois_info,
                "dns_info": dns_info,
                "ssl_info": ssl_info,
                "html_info": html_info,

                # AI Risk Engine
                "risk": risk,
                "ml_prediction": ml_prediction,
                "vt_prediction": vt_prediction,
                "overall_verdict": overall_verdict,
                # Overall Result
                "overall": overall,
            }

    from pprint import pprint

    # Print all context variables
    print("\n========== CONTEXT ==========")
    pprint(context)
    print("=============================\n")

    return render(request, "home.html", context)        