import os


class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", "postgresql:///nysdos_notaries_test"
    )
    SECRET_KEY = os.getenv("SECRET_KEY", "count_duckula")
    WTF_CSRF_ENABLED = False  # Enable CSRF protection
    WTF_CSRF_SECRET_KEY = os.getenv("WTF_CSRF_SECRET_KEY", "count_duckula")
    SECURITY_PASSWORD_SALT = os.getenv("SECURITY_PASSWORD_SALT", "count_duckula")
    SECURITY_REGISTERABLE = os.getenv("SECURITY_REGISTERABLE", False)
    SECURITY_SEND_REGISTER_EMAIL = os.getenv("SECURITY_SEND_REGISTER_EMAIL", False)
    NOTARIOUS_TEST_BUCKET = os.getenv("NOTARIOUS_TEST_BUCKET", "notarious_test_bucket")
    GOOGLE_APPLICATION_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    UPLOAD_FOLDER = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "test_docs", "upload_folder"
    )
