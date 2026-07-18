import requests
from bs4 import BeautifulSoup

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "password", "bank", "secure",
    "account", "confirm", "update", "credit card", "paypal"
]


def analyze_html(url):

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=True
        )

        soup = BeautifulSoup(response.text, "lxml")

        # ============================
        # FORMS ANALYSIS
        # ============================
        forms = soup.find_all("form")

        login_forms = 0
        external_forms = 0
        password_inputs = 0

        for form in forms:
            action = form.get("action", "")

            if action and action.startswith("http"):
                external_forms += 1

            if form.find("input", {"type": "password"}):
                login_forms += 1
                password_inputs += 1

        # ============================
        # IFRAMES ANALYSIS
        # ============================
        hidden_iframes = 0

        for iframe in soup.find_all("iframe"):
            style = iframe.get("style", "").lower()
            width = iframe.get("width", "")
            height = iframe.get("height", "")

            if (
                "display:none" in style
                or width == "0"
                or height == "0"
            ):
                hidden_iframes += 1

        # ============================
        # SCRIPTS ANALYSIS
        # ============================
        external_scripts = len(
            [s for s in soup.find_all("script") if s.get("src")]
        )

        # ============================
        # META REDIRECT CHECK
        # ============================
        meta_redirect = bool(
            soup.find("meta", attrs={
                "http-equiv": lambda x: x and x.lower() == "refresh"
            })
        )

        # ============================
        # KEYWORD ANALYSIS
        # ============================
        page_text = soup.get_text().lower()

        found_keywords = [
            kw for kw in SUSPICIOUS_KEYWORDS if kw in page_text
        ]

        keyword_density = len(found_keywords)

        # ============================
        # RISK SIGNALS (NEW IMPORTANT PART)
        # ============================
        risk_flags = []

        if login_forms > 0:
            risk_flags.append("Login form detected")

        if external_forms > 0:
            risk_flags.append("External form submission detected")

        if hidden_iframes > 0:
            risk_flags.append("Hidden iframe detected")

        if meta_redirect:
            risk_flags.append("Meta redirect detected")

        if keyword_density >= 3:
            risk_flags.append("High phishing keyword density")

        # ============================
        # FINAL SCORE (simple internal scoring)
        # ============================
        score = 0
        score += login_forms * 15
        score += external_forms * 10
        score += hidden_iframes * 20
        score += external_scripts * 2
        score += keyword_density * 5

        if meta_redirect:
            score += 10

        # ============================
        # RETURN
        # ============================
        return {
            "success": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "title": soup.title.string.strip() if soup.title and soup.title.string else "",
            "forms": len(forms),

            "login_forms": login_forms,
            "password_inputs": password_inputs,
            "external_forms": external_forms,

            "hidden_iframes": hidden_iframes,
            "external_scripts": external_scripts,
            "meta_redirect": meta_redirect,

            "keyword_count": keyword_density,
            "keywords": found_keywords,

            # 🔥 NEW IMPORTANT OUTPUTS
            "score": score,
            "risk_flags": risk_flags
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e),

            # 🔥 IMPORTANT: treat failure as security signal
            "score": 40,
            "risk_flags": [
                "HTML analysis failed (possible bot blocking or cloaking)"
            ]
        }