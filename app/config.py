"""
AuthGuard Application Configuration
===================================
Centralized Pydantic v2 settings for environment management, database routing,
SSRF security policies, session handling, and reporting paths.
"""

from pathlib import Path
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Core Application
    APP_NAME: str = "AuthGuard"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    SECRET_KEY: str = "authguard-super-secure-production-ready-secret-key-32bytes-min!"
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Database
    DATABASE_URL: str = "sqlite:///./authguard.db"
    DB_ECHO: bool = False

    # Security & Sessions
    SESSION_COOKIE_NAME: str = "authguard_session"
    SESSION_MAX_AGE_SECONDS: int = 86400  # 24 hours
    SESSION_SECURE_COOKIE: bool = False  # Set to True in HTTPS production
    SESSION_SAME_SITE: str = "lax"
    BCRYPT_ROUNDS: int = 12

    # Assessment Engine Constraints & Safety
    DEFAULT_REQUEST_BUDGET: int = 250
    MAX_REQUEST_BUDGET: int = 1000
    REQUEST_TIMEOUT_SECONDS: float = 10.0
    CONNECT_TIMEOUT_SECONDS: float = 5.0
    MAX_CONCURRENCY: int = 5
    RATE_LIMIT_DELAY_SECONDS: float = 0.2
    CIRCUIT_BREAKER_MAX_5XX: int = 4

    # Target Scope & SSRF Policy
    ALLOW_LOCAL_TARGETS_FOR_TESTING: bool = True  # Permitted for local lab testbed
    BLOCKED_IP_NETWORKS: List[str] = Field(
        default_factory=lambda: [
            "169.254.169.254/32",  # AWS/GCP/Azure instance metadata
            "100.100.100.200/32",  # Alibaba metadata
            "fd00::/8",            # IPv6 Unique Local
        ]
    )

    # Storage Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    STORAGE_DIR: Path = BASE_DIR / "storage"
    REPORTS_DIR: Path = STORAGE_DIR / "reports"
    EVIDENCE_DIR: Path = STORAGE_DIR / "evidence"

    def ensure_directories(self) -> None:
        self.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        self.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_directories()
