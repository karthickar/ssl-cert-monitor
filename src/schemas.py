from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class URLMonitorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=1, max_length=2048, description="HTTPS URL or hostname")
    port: int | None = Field(default=None, ge=1, le=65535)
    location: str | None = Field(default=None, max_length=160)
    alert_enabled: bool = False


class MonitorResponse(BaseModel):
    id: int
    name: str
    kind: Literal["url", "uploaded_certificate"]
    hostname: str | None
    port: int | None
    location: str | None
    alert_enabled: bool
    alert_threshold_days: int | None = None
    alert_recipient_emails: str = ""
    alert_webhook_url: str | None = None
    status: str
    last_error: str | None
    subject: str | None
    issuer: str | None
    serial_number: str | None
    expires_at: datetime | None
    days_remaining: int | None
    last_checked_at: datetime | None
    created_at: datetime
    owner_id: int | None = None
    owner_email: str | None = None
    can_manage: bool = False

    model_config = {"from_attributes": True}


class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    picture: str | None = None

    model_config = {"from_attributes": True}


class DevLoginRequest(BaseModel):
    email: str = Field(default="tester@gmail.com", min_length=5, max_length=255)
    name: str = Field(default="Test User", min_length=1, max_length=160)


class AlertConfigUpdate(BaseModel):
    monitor_id: int
    alert_enabled: bool = True
    expiration_threshold_days: int = Field(ge=1, le=365)
    webhook_url: str | None = Field(default=None, max_length=2048)
    recipient_emails: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("webhook_url")
    @classmethod
    def validate_webhook_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        url = value.strip()
        if not url:
            return None
        if not url.startswith(("http://", "https://")):
            raise ValueError("Webhook URL must start with http:// or https://")
        return url

    @field_validator("recipient_emails")
    @classmethod
    def validate_recipient_emails(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            email = value.strip().lower()
            if not email or "@" not in email or email.startswith("@") or email.endswith("@"):
                raise ValueError("Each recipient must be a valid email address")
            cleaned.append(email)
        return cleaned


class MonitorAlertUpdate(BaseModel):
    alert_enabled: bool


class AlertConfigResponse(BaseModel):
    monitor_id: int | None = None
    alert_enabled: bool | None = None
    expiration_threshold_days: int
    webhook_url: str | None
    recipient_emails: list[str]
