# from datetime import datetime
# from urllib.parse import urlparse
# import whois


# def get_whois_info(url):
#     """
#     Returns WHOIS information for a URL.
#     """

#     try:
#         # Extract domain
#         domain = urlparse(url).netloc

#         if domain.startswith("www."):
#             domain = domain[4:]

#         w = whois.whois(domain)

#         # -------------------------
#         # Creation Date
#         # -------------------------
#         creation_date = w.creation_date

#         if isinstance(creation_date, list):
#             creation_date = creation_date[0]

#         # -------------------------
#         # Expiration Date
#         # -------------------------
#         expiration_date = w.expiration_date

#         if isinstance(expiration_date, list):
#             expiration_date = expiration_date[0]

#         # -------------------------
#         # Updated Date
#         # -------------------------
#         updated_date = w.updated_date

#         if isinstance(updated_date, list):
#             updated_date = updated_date[0]

#         # -------------------------
#         # Domain Age
#         # -------------------------
#         domain_age_days = None

#         if creation_date:
#             domain_age_days = (
#                 datetime.now() - creation_date
#             ).days

#         # -------------------------
#         # Registration Length
#         # -------------------------
#         registration_days = None

#         if creation_date and expiration_date:
#             registration_days = (
#                 expiration_date - creation_date
#             ).days

#         return {

#             "success": True,

#             "domain": domain,

#             "registrar": w.registrar,

#             "creation_date": creation_date,

#             "expiration_date": expiration_date,

#             "updated_date": updated_date,

#             "domain_age_days": domain_age_days,

#             "registration_days": registration_days,

#             "country": w.country,

#             "name_servers": w.name_servers,

#             "emails": w.emails,

#             "status": w.status

#         }

#     except Exception as e:

#         return {

#             "success": False,

#             "error": str(e)

#         }




from datetime import datetime, timezone
from urllib.parse import urlparse
import whois


# =========================
# SAFE DATE NORMALIZER
# =========================
def normalize_date(value):
    try:
        if isinstance(value, list):
            value = value[0] if value else None

        if value is None:
            return None

        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except:
                return None

        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)

        return value

    except:
        return None


# =========================
# CLEAN EMAILS
# =========================
def clean_emails(emails):
    if not emails:
        return []

    if isinstance(emails, str):
        emails = [emails]

    cleaned = []
    for e in emails:
        if not e:
            continue

        e = str(e)
        e = e.replace("mailto:", "")
        e = e.replace("[", "").replace("]", "")

        cleaned.append(e)

    return cleaned


# =========================
# WHOIS MAIN FUNCTION
# =========================
def get_whois_info(url):

    try:
        domain = urlparse(url).netloc

        if domain.startswith("www."):
            domain = domain[4:]

        w = whois.whois(domain)

        creation_date = normalize_date(w.creation_date)
        expiration_date = normalize_date(w.expiration_date)
        updated_date = normalize_date(w.updated_date)

        domain_age_days = None
        if creation_date:
            domain_age_days = (datetime.now(timezone.utc) - creation_date).days

        registration_days = None
        if creation_date and expiration_date:
            registration_days = (expiration_date - creation_date).days

        return {
            "success": True,
            "domain": domain,
            "registrar": w.registrar or "Unknown",
            "creation_date": creation_date.strftime("%Y-%m-%d") if creation_date else None,
            "expiration_date": expiration_date.strftime("%Y-%m-%d") if expiration_date else None,
            "updated_date": updated_date.strftime("%Y-%m-%d") if updated_date else None,
            "domain_age_days": domain_age_days,
            "registration_days": registration_days,
            "country": w.country or "Unknown",
            "name_servers": w.name_servers or [],
            "emails": clean_emails(w.emails),
            "status": w.status or []
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }