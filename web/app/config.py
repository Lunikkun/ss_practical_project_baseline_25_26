from dataclasses import dataclass
import os


@dataclass(frozen=True)
class AppSettings:
    secret_key: str
    upload_folder: str
    max_upload_bytes: int
    force_https: bool
    hsts_max_age: int
    app_security_profile: str
    session_cookie_samesite: str
    session_cookie_secure: bool
    login_ip_rate_limit: int
    login_ip_rate_window: int
    login_lockout_threshold: int
    login_lockout_duration: int
    upload_rate_limit: int
    upload_rate_window: int
    user_max_files: int
    user_storage_quota_bytes: int
    global_storage_quota_bytes: int
    min_free_disk_bytes: int
    db_host: str | None
    db_port: str | None
    db_user: str | None
    db_password: str | None
    db_name: str | None

    @classmethod
    def from_env(cls):
        force_https = os.getenv("FORCE_HTTPS", "0") == "1"
        secure_cookie_from_env = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
        return cls(
            secret_key=os.getenv("SECRET_KEY", ""),
            upload_folder="uploads",
            max_upload_bytes=int(os.getenv("MAX_UPLOAD_BYTES", "0")),
            force_https=force_https,
            hsts_max_age=int(os.getenv("HSTS_MAX_AGE", "31536000")),
            app_security_profile=os.getenv("APP_SECURITY_PROFILE", "dev").lower(),
            session_cookie_samesite=os.getenv("SESSION_COOKIE_SAMESITE", "Lax"),
            session_cookie_secure=secure_cookie_from_env or force_https,
            login_ip_rate_limit=int(os.getenv("LOGIN_IP_RATE_LIMIT", "50")),
            login_ip_rate_window=60,
            login_lockout_threshold=int(os.getenv("LOGIN_LOCKOUT_THRESHOLD", "5")),
            login_lockout_duration=int(os.getenv("LOGIN_LOCKOUT_DURATION", "300")),
            upload_rate_limit=int(os.getenv("UPLOAD_RATE_LIMIT", "25")),
            upload_rate_window=int(os.getenv("UPLOAD_RATE_WINDOW", "60")),
            user_max_files=int(os.getenv("USER_MAX_FILES", "0")),
            user_storage_quota_bytes=int(os.getenv("USER_STORAGE_QUOTA_BYTES", "0")),
            global_storage_quota_bytes=int(os.getenv("GLOBAL_STORAGE_QUOTA_BYTES", "0")),
            min_free_disk_bytes=int(os.getenv("MIN_FREE_DISK_BYTES", "10485760")),
            db_host=os.getenv("DB_HOST"),
            db_port=os.getenv("DB_PORT"),
            db_user=os.getenv("DB_USER"),
            db_password=os.getenv("DB_PASSWORD"),
            db_name=os.getenv("DB_NAME"),
        )
