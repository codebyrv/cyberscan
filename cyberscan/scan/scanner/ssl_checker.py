import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime


def get_ssl_info(url):
    """
    Fetch SSL certificate information.
    """

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname

        port = 443

        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=10) as sock:

            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:

                certificate = secure_sock.getpeercert()

        issuer = dict(x[0] for x in certificate["issuer"])

        subject = dict(x[0] for x in certificate["subject"])

        issued_to = subject.get("commonName")

        issued_by = issuer.get("commonName")

        not_before = datetime.strptime(
            certificate["notBefore"],
            "%b %d %H:%M:%S %Y %Z"
        )

        not_after = datetime.strptime(
            certificate["notAfter"],
            "%b %d %H:%M:%S %Y %Z"
        )

        days_left = (not_after - datetime.utcnow()).days

        return {

            "success": True,

            "https": parsed.scheme == "https",

            "issued_to": issued_to,

            "issued_by": issued_by,

            "valid_from": not_before,

            "valid_until": not_after,

            "days_left": days_left,

            "expired": days_left < 0

        }

    except Exception as e:

        return {

            "success": False,

            "https": False,

            "error": str(e)

        }