import logging

from fastapi import Depends, FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from src.api.routes import router
from src.config import get_settings
from src.database import Base, engine, get_db
from src.models import Monitor

settings = get_settings()
logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")

app = FastAPI(title="SSL Certificate Monitor", version="1.0.0", description="Monitor TLS certificates on URLs and uploaded certificate files.")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


def ensure_database_schema() -> None:
    """Create new tables and add dashboard columns for existing local SQLite databases."""
    Base.metadata.create_all(bind=engine)
    existing_columns = {column["name"] for column in inspect(engine).get_columns("monitors")}
    with engine.begin() as connection:
        if "location" not in existing_columns:
            connection.execute(text("ALTER TABLE monitors ADD COLUMN location VARCHAR(160)"))
        if "alert_enabled" not in existing_columns:
            connection.execute(text("ALTER TABLE monitors ADD COLUMN alert_enabled BOOLEAN NOT NULL DEFAULT 1"))
    alert_columns = {column["name"] for column in inspect(engine).get_columns("alert_config")}
    if "recipient_emails" not in alert_columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE alert_config ADD COLUMN recipient_emails TEXT NOT NULL DEFAULT ''"))


@app.on_event("startup")
def startup() -> None:
    ensure_database_schema()


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/route")


@app.get("/route", include_in_schema=False)
def dashboard(request: Request, db: Session = Depends(get_db)):
    monitors = db.query(Monitor).order_by(Monitor.id.asc()).all()
    from src.services.monitoring import get_alert_config, recipient_emails
    config = get_alert_config(db)
    return templates.TemplateResponse(request=request, name="dashboard.html", context={
        "monitors": monitors, "alert_config": config, "recipient_emails": recipient_emails(config),
    })


app.include_router(router)
