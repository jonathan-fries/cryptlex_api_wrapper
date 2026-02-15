import json
import os

import boto3

CRYPTLEX_BASE_URL = os.environ.get("CRYPTLEX_BASE_URL", "https://api.cryptlex.com/v3")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "cryptlex-wrapper-api-keys")
CRYPTLEX_SECRET_NAME = os.environ.get("CRYPTLEX_SECRET_NAME", "cryptlex-api-credentials")

_secrets_cache = {}


def get_cryptlex_credentials():
    """Retrieve Cryptlex credentials from AWS Secrets Manager (cached)."""
    if "credentials" in _secrets_cache:
        return _secrets_cache["credentials"]

    client = boto3.client("secretsmanager")
    resp = client.get_secret_value(SecretId=CRYPTLEX_SECRET_NAME)
    creds = json.loads(resp["SecretString"])
    _secrets_cache["credentials"] = creds
    return creds
