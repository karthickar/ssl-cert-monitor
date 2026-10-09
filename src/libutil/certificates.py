from dataclasses import dataclass
from datetime import UTC, datetime
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import serialization


@dataclass(frozen=True)
class CertificateDetails:
    subject: str
    issuer: str
    serial_number: str
    expires_at: datetime
    days_remaining: int


def _details(certificate: x509.Certificate) -> CertificateDetails:
    expires_at = certificate.not_valid_after_utc.replace(tzinfo=None)
    now = datetime.now(UTC).replace(tzinfo=None)
    return CertificateDetails(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=format(certificate.serial_number, "X"),
        expires_at=expires_at,
        days_remaining=(expires_at - now).days,
    )


def inspect_pem_certificate(content: bytes) -> tuple[str, CertificateDetails]:
    """Validate an uploaded PEM/DER certificate and return canonical PEM plus metadata."""
    try:
        certificate = x509.load_pem_x509_certificate(content)
    except ValueError:
        try:
            certificate = x509.load_der_x509_certificate(content)
        except ValueError as error:
            raise ValueError("File is not a valid PEM or DER X.509 certificate") from error
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return pem, _details(certificate)


def fetch_server_certificate(hostname: str, port: int, timeout: int) -> CertificateDetails:
    """Read the leaf certificate without requiring a trusted chain (useful for internal TLS)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=timeout) as connection:
        with context.wrap_socket(connection, server_hostname=hostname) as tls_socket:
            der = tls_socket.getpeercert(binary_form=True)
    if not der:
        raise ValueError("Server did not present a certificate")
    certificate = x509.load_der_x509_certificate(der)
    return _details(certificate)
