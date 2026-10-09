from urllib.parse import urlparse


def parse_target(value: str, explicit_port: int | None = None) -> tuple[str, int]:
    """Return a host and port from a hostname or URL; HTTPS is the only URL scheme."""
    candidate = value.strip()
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are supported")
    if not parsed.hostname:
        raise ValueError("A valid hostname is required")
    try:
        parsed_port = parsed.port
    except ValueError as error:
        raise ValueError("Port must be between 1 and 65535") from error
    return parsed.hostname, explicit_port or parsed_port or 443
