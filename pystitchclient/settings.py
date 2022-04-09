from pydantic import BaseSettings, Field
from typing import (List)

class Settings(BaseSettings):
    log_level: str = Field(env="LOG_LEVEL")
    stitch_client_id: str = Field(env="STITCH_CLIENT_ID")
    stitch_redirect_uri: str = Field(env="STITCH_REDIRECT_URI")
    stitch_client_certificate: str = Field(env="STITCH_CLIENT_CERTIFICATE")
    class Config:
        env_file = ".env"

settings = Settings()
