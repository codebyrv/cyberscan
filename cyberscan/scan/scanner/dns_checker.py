import dns.resolver
from urllib.parse import urlparse


def get_dns_info(url):
    """
    Fetch DNS information for a domain.
    """

    try:
        domain = urlparse(url).netloc

        if domain.startswith("www."):
            domain = domain[4:]

        dns_info = {
            "success": True,
            "domain": domain,
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": []
        }

        # ---------------- A Record ----------------
        try:
            answers = dns.resolver.resolve(domain, "A")
            dns_info["a_records"] = [str(r) for r in answers]
        except Exception:
            dns_info["a_records"] = []

        # ---------------- MX Record ----------------
        try:
            answers = dns.resolver.resolve(domain, "MX")
            dns_info["mx_records"] = [
                str(r.exchange) for r in answers
            ]
        except Exception:
            dns_info["mx_records"] = []

        # ---------------- NS Record ----------------
        try:
            answers = dns.resolver.resolve(domain, "NS")
            dns_info["ns_records"] = [
                str(r.target) for r in answers
            ]
        except Exception:
            dns_info["ns_records"] = []

        # ---------------- TXT Record ----------------
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            dns_info["txt_records"] = [
                str(r) for r in answers
            ]
        except Exception:
            dns_info["txt_records"] = []

        dns_info["exists"] = (
            len(dns_info["a_records"]) > 0
        )

        return dns_info

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }