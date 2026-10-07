from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SOCForge API"
    app_version: str = "0.1.0"
    debug: bool = False

    elastic_url: str = "http://localhost:9200"
    elastic_username: str | None = None
    elastic_password: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()