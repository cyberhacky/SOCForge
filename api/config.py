from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SOCForge API"
    app_version: str = "0.1.0"
    debug: bool = False
    socforge_api_key: SecretStr | None = None

    elastic_url: str = "https://localhost:9200"
    elastic_username: str | None = None
    elastic_password: str | None = None
    elastic_ca_cert: str | None = None

    postgres_db: str = "socforge"
    postgres_user: str = "socforge"
    postgres_password: str = ""
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    abuseipdb_api_key: str | None = None
    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"
    abuseipdb_timeout_seconds: float = Field(default=10.0, gt=0)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
