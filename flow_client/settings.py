"""
Configuration for the USPS microservice settings.
Context is switched based on if the app is in debug mode.
"""
import os

# SECURITY WARNING: don't run with debug turned on in production!
# DEBUG set is set to True if env var is "True"
DEBUG = os.getenv("DEBUG", "False") == "True"

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
OIDC_URL = os.getenv("URL")

USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")

FLOW_ISSUER = os.getenv("FLOW_ISSUER")
FLOW_URL = os.getenv("FLOW_URL")
FLOW_CLIENT_ID = os.getenv("FLOW_CLIENT_ID")
FLOW_CLIENT_SECRET = os.getenv("FLOW_CLIENT_SECRET")

FLOW_REDIRECT_URI = os.getenv("FLOW_REDIRECT_URI")

FLOW_PRIVATE_KEY = bytes(os.getenv("FLOW_PRIVATE_KEY",""), "utf-8").decode('unicode_escape')
FLOW_PUBLIC_KEY = bytes(os.getenv("FLOW_PUBLIC_KEY",""), "utf-8").decode('unicode_escape')
