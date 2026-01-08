from  pydantic_settings import BaseSettings

class Settings(BaseSettings):
    FRONT_END_BASE_URL: str = ""

    # Database settings
    DATABASE_URL: str = ""
    REDIS_URL: str = ""

    # Security settings
    SECRETE_KEY: str = ""
    ALGORITHM: str = ""
    
    # API keys
    RESEND_API_KEY: str = ""
    
    # Expiration times
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = 0
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 0
    REFRESH_TOKEN_EXPIRE_DAYS: int = 0
    RESET_PASSWORD_TOKEN_EXPIRE_MINUTES: int = 0

    # Google client ID
    GOOGLE_CLIENT_ID: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()