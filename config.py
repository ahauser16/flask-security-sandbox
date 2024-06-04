import os


class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", "postgresql:///nysdos_notaries_test"
    )
    SECRET_KEY = os.getenv("SECRET_KEY", "count_duckula")
    SECURITY_PASSWORD_SALT = os.getenv("SECURITY_PASSWORD_SALT", "count_duckula")
    SECURITY_REGISTERABLE = os.getenv("SECURITY_REGISTERABLE", False)
    SECURITY_SEND_REGISTER_EMAIL = os.getenv("SECURITY_SEND_REGISTER_EMAIL", False)
    NOTARIOUS_TEST_BUCKET = os.getenv("NOTARIOUS_TEST_BUCKET", "notarious_test_bucket")


# In this file, we define a Config class with class variables for each of your configuration settings. We use the os.getenv() function to get the value of each setting from an environment variable. The second argument to os.getenv() is a default value to use if the environment variable is not set. This is useful for setting default values for configuration settings that are not required.
