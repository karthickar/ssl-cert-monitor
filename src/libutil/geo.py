import ipaddress
import logging

import httpx
from fastapi import Request

logger = logging.getLogger(__name__)

COUNTRY_NAMES = {
    "AE": "United Arab Emirates",
    "AU": "Australia",
    "CA": "Canada",
    "DE": "Germany",
    "FR": "France",
    "GB": "United Kingdom",
    "IN": "India",
    "NL": "Netherlands",
    "SA": "Saudi Arabia",
    "SG": "Singapore",
    "US": "United States",
}


def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _name_from_code(code: str) -> str:
    return COUNTRY_NAMES.get(code.upper(), code.upper())


def detect_country(request: Request) -> str:
    """Return the country associated with the current request, or Unknown."""
    header = (request.headers.get("cf-ipcountry") or request.headers.get("x-appengine-country") or "").strip()
    if len(header) == 2 and header.upper() not in {"XX", "T1"}:
        return _name_from_code(header)
    if header and len(header) > 2:
        return header
    ip = client_ip(request)
    query = ip if ip and _is_public(ip) else ""
    try:
        url = f"http://ip-api.com/json/{query}" if query else "http://ip-api.com/json/"
        response = httpx.get(url, params={"fields": "status,country"}, timeout=2.0)
        data = response.json()
        if data.get("status") == "success" and data.get("country"):
            return str(data["country"])
    except Exception as error:
        logger.info("Country lookup failed: %s", error)
    return "Unknown"
