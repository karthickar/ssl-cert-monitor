import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
TEST_DB = Path(f"/tmp/ssl-monitor-test-{os.getpid()}.db")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["DISABLE_SCHEDULER"] = "true"
os.environ["AUTH_ALLOW_DEV_LOGIN"] = "true"
os.environ["SESSION_SECRET_KEY"] = "test-secret"

from fastapi.testclient import TestClient  # noqa: E402
from src.database import SessionLocal  # noqa: E402
from src.main import app  # noqa: E402
from src.models import Monitor  # noqa: E402
from src.services.monitoring import check_all_monitors  # noqa: E402


client = TestClient(app)


def _sign_out():
    client.cookies.clear()


def _sign_in(email: str = "tester@gmail.com", name: str = "Tester"):
    _sign_out()
    response = client.post("/auth/dev-login", json={"email": email, "name": name})
    assert response.status_code == 200
    return response.json()


def _sample_certificate_bytes() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def test_health_and_alert_configuration():
    with client:
        _sign_out()
        assert client.get("/health").json() == {"status": "ok"}
        assert client.put("/api/v1/alert-config", json={"expiration_threshold_days": 14}).status_code == 401
        _sign_in()
        initial = client.get("/api/v1/alert-config")
        assert initial.status_code == 200
        changed = client.put("/api/v1/alert-config", json={"expiration_threshold_days": 14})
        assert changed.status_code == 200
        assert changed.json()["expiration_threshold_days"] == 14


def test_url_validation_and_listing():
    with client:
        _sign_in()
        bad = client.post("/api/v1/monitors/url", json={"name": "invalid", "url": "http://example.com"})
        assert bad.status_code == 422
        monitors = client.get("/api/v1/monitors")
        assert monitors.status_code == 200
        assert isinstance(monitors.json(), list)


def test_login_required_for_mutations_and_owner_can_delete():
    with client:
        _sign_out()
        create = client.post("/api/v1/monitors/url", json={"name": "Example", "url": "https://example.com"})
        assert create.status_code == 401
        owner = _sign_in("owner@gmail.com", "Owner")
        created = client.post("/api/v1/monitors/certificate", params={"name": "Office cert"},
                              files={"certificate": ("cert.pem", _sample_certificate_bytes(), "application/x-pem-file")})
        assert created.status_code == 201
        monitor_id = created.json()["id"]
        assert created.json()["owner_email"] == owner["email"]
        assert created.json()["can_manage"] is True
        assert created.json()["days_remaining"] is not None
        client.get("/auth/logout")
        other = client.post("/auth/dev-login", json={"email": "other@gmail.com", "name": "Other"})
        assert other.status_code == 200
        forbidden = client.delete(f"/api/v1/monitors/{monitor_id}")
        assert forbidden.status_code == 403
        client.get("/auth/logout")
        _sign_in("owner@gmail.com", "Owner")
        removed = client.delete(f"/api/v1/monitors/{monitor_id}")
        assert removed.status_code == 204


def test_daily_refresh_updates_validity():
    with client:
        _sign_in()
        created = client.post("/api/v1/monitors/certificate", params={"name": "Refresh me"},
                              files={"certificate": ("cert.pem", _sample_certificate_bytes(), "application/x-pem-file")})
        assert created.status_code == 201
        monitor_id = created.json()["id"]
        db = SessionLocal()
        monitor = db.get(Monitor, monitor_id)
        monitor.days_remaining = 999
        monitor.status = "pending"
        db.commit()
        db.close()
        assert check_all_monitors() >= 1
        refreshed = client.get(f"/api/v1/monitors/{monitor_id}").json()
        assert refreshed["days_remaining"] != 999
        assert refreshed["status"] in {"healthy", "expiring_soon", "expired"}
