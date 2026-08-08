from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SKILLGUARD_", env_file=".env", extra="ignore")

    ingest_max_bytes: int = 100 * 1024 * 1024
    ingest_max_zip_members: int = 10_000
    scan_timeout_s: int = 300
    skillspector_bin: str = "skillspector"
    cisco_bin: str = "skill-scanner"
    cisco_policy: str = "balanced"
    semantic_model: str = "claude-sonnet-4-5"
    anthropic_api_key: str = ""
    danger_min: int = 70
    caution_min: int = 30


@lru_cache
def get_settings() -> Settings:
    return Settings()
