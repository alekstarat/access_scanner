"""
Базовая информация о TLS-соединении и сертификате.
Домены берутся из CN + SAN.
"""
import ssl
import socket
from datetime import datetime, timezone


def probe(ip: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Возвращает:
        ok, error,
        tls_version, cipher,
        cert: { subject_cn, san[], issuer, not_before, not_after, expired, days_left }
        domains: list[str]
    """
    result = {
        "ok": False,
        "error": None,
        "tls_version": None,
        "cipher": None,
        "cert": {},
        "domains": [],
    }

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                result["tls_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["cipher"] = cipher[0]

                der = ssock.getpeercert(binary_form=True)
                if der:
                    cert_info = _parse_der(der)
                    result["cert"] = cert_info
                    result["domains"] = _extract_domains(cert_info)

                result["ok"] = True

    except Exception as exc:
        result["error"] = str(exc)

    return result


def _parse_der(der: bytes) -> dict:
    """Парсинг через cryptography, если установлена; иначе пусто."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import NameOID, ExtensionOID

        cert = x509.load_der_x509_certificate(der, default_backend())

        subject_cn = None
        try:
            subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            pass

        issuer = None
        try:
            issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            pass

        san = []
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = [n.lower() for n in ext.value.get_values_for_type(x509.DNSName)]
        except Exception:
            pass

        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
        now = datetime.now(timezone.utc)
        days_left = (cert.not_valid_after_utc - now).days
        expired = days_left < 0

        return {
            "subject_cn": subject_cn,
            "san": san,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "expired": expired,
            "days_left": days_left,
        }
    except ImportError:
        return {"note": "install cryptography for cert details"}
    except Exception as exc:
        return {"error": str(exc)}


def _extract_domains(cert_info: dict) -> list[str]:
    names = set()
    cn = cert_info.get("subject_cn")
    if cn and isinstance(cn, str):
        names.add(cn.lower().rstrip("."))
    for s in cert_info.get("san") or []:
        if isinstance(s, str):
            names.add(s.lower().rstrip("."))
    return sorted(names)
