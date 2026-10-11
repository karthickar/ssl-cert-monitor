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
from src.services.monitoring import check_all_monitors, should_send_expiry_alert  # noqa: E402


client = TestClient(app)


def _sample_certificate_bytes(days_valid: int = 30) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def test_health_and_alert_configuration():
    with client:
        assert client.get("/health").json() == {"status": "ok"}
        missing = client.put("/api/v1/alert-config", json={"expiration_threshold_days": 14})
        assert missing.status_code == 422
        created = client.post("/api/v1/monitors/certificate", params={"name": "Alert cert"},
                              files={"certificate": ("cert.pem", _sample_certificate_bytes(), "application/x-pem-file")})
        assert created.status_code == 201
        changed = client.put("/api/v1/alert-config", json={
            "monitor_id": created.json()["id"],
            "alert_enabled": True,
            "expiration_threshold_days": 14,
        })
        assert changed.status_code == 200
        assert changed.json()["expiration_threshold_days"] == 14
        assert changed.json()["monitor_id"] == created.json()["id"]
        assert changed.json()["alert_enabled"] is True
        db = SessionLocal()
        stored = db.get(Monitor, created.json()["id"])
        assert stored.alert_enabled is True
        assert stored.alert_threshold_days == 14
        assert stored.hostname is None
        assert stored.certificate_pem
        db.close()


def test_url_validation_and_listing():
    with client:
        bad = client.post("/api/v1/monitors/url", json={"name": "invalid", "url": "http://example.com"})
        assert bad.status_code == 422
        monitors = client.get("/api/v1/monitors")
        assert monitors.status_code == 200
        assert isinstance(monitors.json(), list)


def test_operations_work_without_login_and_use_devops_owner():
    with client:
        created = client.post(
            "/api/v1/monitors/certificate",
            params={"name": "Office cert"},
            headers={"cf-ipcountry": "AE"},
            files={"certificate": ("cert.pem", _sample_certificate_bytes(), "application/x-pem-file")},
        )
        assert created.status_code == 201
        body = created.json()
        assert body["owner_email"] == "devops"
        assert body["location"] == "United Arab Emirates"
        assert body["can_manage"] is True
        removed = client.delete(f"/api/v1/monitors/{body['id']}")
        assert removed.status_code == 204


def test_daily_refresh_updates_validity():
    with client:
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


def test_dashboard_shows_remove_and_optional_gmail():
    with client:
        page = client.get("/ssl", headers={"cf-ipcountry": "AE"})
        assert page.status_code == 200
        assert "Sign in with Gmail" in page.text
        assert "Remove" in page.text
        assert "devops" in page.text
        assert "United Arab Emirates" in page.text
        assert "Add a new alerting" in page.text
        assert "No alerts yet" in page.text or "Edit" in page.text


def test_check_sends_email_and_webhook_at_seven_days(monkeypatch):
    sent = {}

    def fake_send(webhook, emails, payload):
        sent["webhook"] = webhook
        sent["emails"] = emails
        sent["payload"] = payload
        return {"webhook": True, "email": True}

    monkeypatch.setattr("src.services.monitoring.send_alerts", fake_send)
    with client:
        created = client.post(
            "/api/v1/monitors/certificate",
            params={"name": "Soon", "alert_enabled": "false"},
            files={"certificate": ("cert.pem", _sample_certificate_bytes(8), "application/x-pem-file")},
        )
        assert created.status_code == 201
        saved = client.put("/api/v1/alert-config", json={
            "monitor_id": created.json()["id"],
            "alert_enabled": True,
            "expiration_threshold_days": created.json()["days_remaining"],
            "recipient_emails": ["ops@example.com"],
            "webhook_url": "https://hooks.example.com/ssl",
        })
        assert saved.status_code == 200
        assert sent["emails"] == ["ops@example.com"]
        assert sent["webhook"] == "https://hooks.example.com/ssl"
        assert sent["payload"]["days_remaining"] == created.json()["days_remaining"]
        assert sent["payload"]["alert_threshold_days"] == created.json()["days_remaining"]


def test_alerts_fire_at_threshold_seven_and_one_day():
    assert should_send_expiry_alert(14, 14, None) is True
    assert should_send_expiry_alert(14, 14, 14) is False
    assert should_send_expiry_alert(7, 14, 14) is True
    assert should_send_expiry_alert(1, 14, 7) is True
    assert should_send_expiry_alert(10, 14, None) is False
    assert should_send_expiry_alert(-1, 14, None) is True
