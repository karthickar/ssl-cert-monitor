import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
TEST_DB = Path(f"/tmp/ssl-monitor-test-{os.getpid()}.db")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"

from fastapi.testclient import TestClient  # noqa: E402
from src.main import app  # noqa: E402


client = TestClient(app)


def test_health_and_alert_configuration():
    with client:
        assert client.get("/health").json() == {"status": "ok"}
        initial = client.get("/api/v1/alert-config")
        assert initial.status_code == 200
        changed = client.put("/api/v1/alert-config", json={"expiration_threshold_days": 14})
        assert changed.status_code == 200
        assert changed.json()["expiration_threshold_days"] == 14


def test_url_validation_and_listing():
    with client:
        bad = client.post("/api/v1/monitors/url", json={"name": "invalid", "url": "http://example.com"})
        assert bad.status_code == 422
        monitors = client.get("/api/v1/monitors")
        assert monitors.status_code == 200
        assert isinstance(monitors.json(), list)
