import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session, joinedload
from starlette.middleware.sessions import SessionMiddleware

from src.api.auth_routes import google_oauth_configured, router as auth_router
from src.api.routes import router
from src.auth import get_optional_user
from src.config import get_settings
from src.database import Base, engine, get_db
from src.models import Monitor, User
from src.services.monitoring import can_manage_monitor, get_alert_config, recipient_emails

settings = get_settings()
logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")
scheduler = BackgroundScheduler()


def ensure_database_schema() -> None:
    """Create new tables and add dashboard columns for existing local SQLite databases."""
    Base.metadata.create_all(bind=engine)
    existing_columns = {column["name"] for column in inspect(engine).get_columns("monitors")}
    with engine.begin() as connection:
        if "location" not in existing_columns:
            connection.execute(text("ALTER TABLE monitors ADD COLUMN location VARCHAR(160)"))
        if "alert_enabled" not in existing_columns:
            connection.execute(text("ALTER TABLE monitors ADD COLUMN alert_enabled BOOLEAN NOT NULL DEFAULT 1"))
        if "owner_id" not in existing_columns:
            connection.execute(text("ALTER TABLE monitors ADD COLUMN owner_id INTEGER"))
    alert_columns = {column["name"] for column in inspect(engine).get_columns("alert_config")}
    if "recipient_emails" not in alert_columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE alert_config ADD COLUMN recipient_emails TEXT NOT NULL DEFAULT ''"))


def start_certificate_scheduler() -> None:
    if settings.disable_scheduler:
        return
    from src.services.monitoring import check_all_monitors
    scheduler.add_job(check_all_monitors, "interval", hours=settings.check_interval_hours,
                      id="daily-cert-check", replace_existing=True)
    scheduler.add_job(check_all_monitors, "date", run_date=datetime.utcnow() + timedelta(seconds=3),
                      id="startup-cert-check", replace_existing=True)
    if not scheduler.running:
        scheduler.start()
        logging.getLogger(__name__).info("Certificate refresh scheduled every %s hours", settings.check_interval_hours)


@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_database_schema()
    start_certificate_scheduler()
    yield
    if scheduler.running:
        scheduler.shutdown(wait=False)


app = FastAPI(title="SSL Certificate Monitor", version="1.0.0",
              description="Monitor TLS certificates on URLs and uploaded certificate files.", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret_key)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/ssl")


@app.get("/route", include_in_schema=False)
def legacy_dashboard() -> RedirectResponse:
    return RedirectResponse(url="/ssl")


@app.get("/ssl", include_in_schema=False)
def dashboard(request: Request, db: Session = Depends(get_db), user: User | None = Depends(get_optional_user)):
    monitors = db.query(Monitor).options(joinedload(Monitor.owner)).order_by(Monitor.id.asc()).all()
    config = get_alert_config(db)
    return templates.TemplateResponse(request=request, name="dashboard.html", context={
        "monitors": monitors,
        "alert_config": config,
        "recipient_emails": recipient_emails(config),
        "current_user": user,
        "google_oauth_configured": google_oauth_configured(),
        "dev_login_enabled": settings.auth_allow_dev_login,
        "check_interval_hours": settings.check_interval_hours,
        "can_manage_monitor": can_manage_monitor,
    })


app.include_router(auth_router)
app.include_router(router)
