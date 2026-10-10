# SSL Certificate Monitor

A small FastAPI microservice that checks the leaf TLS certificate presented by public or internal HTTPS services, or tracks an uploaded PEM/DER X.509 certificate. It stores monitors and alert settings in SQLite, making it suitable for a local Docker demonstration.

## Features

- HTTPS URL/hostname monitoring with configurable port (defaults to `443`)
- Internal/self-signed TLS inspection: the connection retrieves the certificate without requiring a trusted chain
- Certificate-file monitoring via upload (`.pem`, `.crt`, `.cer`, or DER content)
- Daily background refresh of certificate validity on the dashboard
- Google/Gmail sign-in; only the signed-in owner can add, change, or remove monitors
- Expiry status, subject, issuer, serial number, expiry date, and remaining days
- Configurable expiring-soon threshold (defaults to 7 days)
- Optional JSON webhook alerting; without a webhook, alerts are written to the application log for easy local testing
- SQLite persistence, input validation, structured API errors, and a health endpoint

## Layout

```text
src/
  api/routes.py             REST endpoints
  services/monitoring.py    monitor orchestration and persistence
  libutil/                  reusable TLS, URL, and alert helpers
  models.py                 SQLite models
  main.py                   FastAPI application
```

## Run with Docker

From this directory:

```bash
docker build -t ssl-certificate-monitor .
docker run --rm -p 8000:8000 -v "$(pwd)/data:/app/data" --name ssl-monitor ssl-certificate-monitor
```

The database is persisted in `./data/ssl_monitor.db`. The dashboard is at <http://localhost:8000/ssl> and the API documentation is at <http://localhost:8000/docs>.

To enable Gmail sign-in, create a Google OAuth client (Web application) and set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `SESSION_SECRET_KEY`, and `OAUTH_REDIRECT_URL`. Authorized redirect URI should match `OAUTH_REDIRECT_URL`, typically `http://localhost:8000/auth/google/callback`. After sign-in, monitors are stored under that Google username. For local UI testing without Google credentials, set `AUTH_ALLOW_DEV_LOGIN=true`.

To change defaults, copy `.env.example` to `.env` and pass it to Docker:

```bash
docker run --rm -p 8000:8000 --env-file .env -v "$(pwd)/data:/app/data" ssl-certificate-monitor
```

## API examples

Health check:

```bash
curl http://localhost:8000/health
```

Create and immediately check a public endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/monitors/url \
  -H 'Content-Type: application/json' \
  -d '{"name":"Example","url":"https://example.com"}'
```

Monitor an internal endpoint on a custom port:

```bash
curl -X POST http://localhost:8000/api/v1/monitors/url \
  -H 'Content-Type: application/json' \
  -d '{"name":"Internal gateway","url":"https://gateway.internal","port":8443}'
```

Upload a certificate to monitor:

```bash
curl -X POST 'http://localhost:8000/api/v1/monitors/certificate?name=VPN%20certificate' \
  -F 'certificate=@./certificate.pem'
```

List monitors or force a fresh check:

```bash
curl http://localhost:8000/api/v1/monitors
curl -X POST http://localhost:8000/api/v1/monitors/1/check
```

Set a 14-day alert threshold and webhook. The webhook receives a JSON event whenever a successful check finds a certificate at or under the threshold:

```bash
curl -X PUT http://localhost:8000/api/v1/alert-config \
  -H 'Content-Type: application/json' \
  -d '{"expiration_threshold_days":14,"webhook_url":"https://hooks.example.net/ssl-alerts"}'
curl -X POST http://localhost:8000/api/v1/alert-config/test
```

When no webhook is configured, use the test endpoint above or check a monitor and inspect the container log; the alert payload is logged locally. Email delivery can be added by implementing another sender alongside `src/libutil/alerts.py` without changing the API or monitor service.

## Local (non-Docker) development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
DATABASE_URL=sqlite:///./data/ssl_monitor.db uvicorn src.main:app --reload
pytest -q
```

## Database options: SQLite or MySQL

SQLite remains the default and is ideal for a local Docker demonstration. To use MySQL, the service uses SQLAlchemy's `mysql+mysqlconnector` driver, supplied by `mysql-connector-python` in `requirements.txt`.

Set these environment variables (or place them in `.env`) and restart the service:

```bash
DATABASE_ENGINE=mysql
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_DATABASE=ssl_monitor
MYSQL_USERNAME=ssl_monitor
MYSQL_PASSWORD='a-password-with-special-characters-is-supported'
```

Create the database and user in MySQL before starting the service:

```sql
CREATE DATABASE ssl_monitor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'ssl_monitor'@'%' IDENTIFIED BY 'choose-a-strong-password';
GRANT ALL PRIVILEGES ON ssl_monitor.* TO 'ssl_monitor'@'%';
FLUSH PRIVILEGES;
```

For a MySQL server running on the Docker host, use `MYSQL_HOST=host.docker.internal` on Docker Desktop. `DATABASE_URL` remains available as an override when you already have a complete SQLAlchemy connection URL. The application creates its tables on startup; use a migration tool for controlled production schema changes.

## Kubernetes with Skaffold

The `skaffold.yaml` builds the existing Dockerfile locally and deploys the manifests in `k8s/`. It creates a `ClusterIP` service and a 1 GiB persistent volume claim for the SQLite database.

For email alerts, create the optional SMTP Secret before deploying. Do not apply `k8s/secret.example.yaml` unchanged because it contains placeholders:

```bash
kubectl create secret generic ssl-monitor-secrets \
  --from-literal=SMTP_HOST=smtp.example.com \
  --from-literal=SMTP_PORT=587 \
  --from-literal=SMTP_USERNAME=alerts@example.com \
  --from-literal=SMTP_PASSWORD='your-app-password' \
  --from-literal=SMTP_FROM_EMAIL=alerts@example.com
skaffold dev
```

For a one-time deployment, use `skaffold run`. To open the dashboard locally after deployment:

```bash
kubectl port-forward service/ssl-certificate-monitor 8000:80
```

Then visit <http://localhost:8000/ssl>. Local clusters such as Docker Desktop, Minikube, or kind need a default storage class for the PVC. For production, replace the SQLite PVC with an external database and use a managed secret store.

## Notes

- URL monitor creation attempts an immediate check. If DNS/network/TLS negotiation fails, the monitor is retained with status `error` and can be checked again later.
- Certificate validity is refreshed on a background schedule (default every 24 hours) and written back to the dashboard. You can still request an immediate owner-only check through `POST /api/v1/monitors/{id}/check`.
- Uploaded certificate data is stored inside the local SQLite database. Protect the database volume appropriately.
