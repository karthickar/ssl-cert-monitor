from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    google_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    picture: Mapped[Optional[str]] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now())
    monitors: Mapped[list["Monitor"]] = relationship(back_populates="owner")


class Monitor(Base):
    __tablename__ = "monitors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # url or uploaded_certificate
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    port: Mapped[Optional[int]] = mapped_column(Integer)
    location: Mapped[Optional[str]] = mapped_column(String(160))
    alert_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    certificate_pem: Mapped[Optional[str]] = mapped_column(Text)
    owner: Mapped[Optional["User"]] = relationship(back_populates="monitors")
    status: Mapped[str] = mapped_column(String(30), default="pending", nullable=False)
    last_error: Mapped[Optional[str]] = mapped_column(Text)
    subject: Mapped[Optional[str]] = mapped_column(String(500))
    issuer: Mapped[Optional[str]] = mapped_column(String(500))
    serial_number: Mapped[Optional[str]] = mapped_column(String(200))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False))
    days_remaining: Mapped[Optional[int]] = mapped_column(Integer)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now(), onupdate=func.now())


class AlertConfig(Base):
    __tablename__ = "alert_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    expiration_threshold_days: Mapped[int] = mapped_column(Integer, nullable=False)
    webhook_url: Mapped[Optional[str]] = mapped_column(String(2048))
    recipient_emails: Mapped[str] = mapped_column(Text, default="", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now(), onupdate=func.now())
