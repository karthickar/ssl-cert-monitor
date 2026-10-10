from functools import lru_cache
from urllib.parse import quote_plus

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # DATABASE_URL overrides the individual database settings below.
    database_url: str | None = None
    database_engine: str = "sqlite"
    sqlite_database_path: str = "/app/data/ssl_monitor.db"
    mysql_host: str | None = None
    mysql_port: int = Field(default=3306, ge=1, le=65535)
    mysql_database: str = "ssl_monitor"
    mysql_username: str | None = None
    mysql_password: str | None = None
    default_expiry_threshold_days: int = Field(default=7, ge=1, le=365)
    check_timeout_seconds: int = Field(default=10, ge=1, le=60)
    log_level: str = "INFO"
    default_webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    smtp_use_tls: bool = True
    session_secret_key: str = "change-me-in-production"
    google_client_id: str | None = None
    google_client_secret: str | None = None
    oauth_redirect_url: str | None = None
    check_interval_hours: int = Field(default=24, ge=1, le=168)
    disable_scheduler: bool = False
    auth_allow_dev_login: bool = False

    @property
    def resolved_database_url(self) -> str:
        """Return an SQLAlchemy URL, with mysql-connector as the MySQL driver."""
        if self.database_url:
            return self.database_url
        if self.database_engine.lower() == "sqlite":
            return f"sqlite:///{self.sqlite_database_path}"
        if self.database_engine.lower() != "mysql":
            raise ValueError("DATABASE_ENGINE must be either 'sqlite' or 'mysql'")
        if not all([self.mysql_host, self.mysql_username, self.mysql_password, self.mysql_database]):
            raise ValueError("MYSQL_HOST, MYSQL_USERNAME, MYSQL_PASSWORD, and MYSQL_DATABASE are required for MySQL")
        username = quote_plus(self.mysql_username)
        password = quote_plus(self.mysql_password)
        database = quote_plus(self.mysql_database)
        return f"mysql+mysqlconnector://{username}:{password}@{self.mysql_host}:{self.mysql_port}/{database}?charset=utf8mb4"


@lru_cache
def get_settings() -> Settings:
    return Settings()
