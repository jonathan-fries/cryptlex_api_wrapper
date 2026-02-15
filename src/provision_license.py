"""Lambda handler: POST /licenses

Provisions a new Cryptlex license.

Request body (JSON):
    product_id  (str, optional): Cryptlex product ID. Falls back to the
                                 default product ID stored in Secrets Manager.
    allowed_activations (int, optional): Number of allowed activations.
    type (str, optional): "node-locked" | "hosted-floating" | "on-premise-floating"
    validity (int, optional): Duration in seconds until the license expires.
    metadata (list[dict], optional): Key/value metadata pairs.

    Any additional Cryptlex license fields can be passed and will be forwarded
    as-is to the Cryptlex API.

Response (200):
    The full license object returned by Cryptlex, including the generated key.
"""

import json
import logging
import traceback

import requests

from src.auth import validate_api_key
from src.config import get_cryptlex_credentials
from src.cryptlex_client import create_license

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Maps our snake_case convenience fields to Cryptlex camelCase.
_FIELD_MAP = {
    "product_id": "productId",
    "allowed_activations": "allowedActivations",
    "allowed_deactivations": "allowedDeactivations",
    "lease_duration": "leaseDuration",
    "server_sync_grace_period": "serverSyncGracePeriod",
    "server_sync_interval": "serverSyncInterval",
    "allowed_clock_offset": "allowedClockOffset",
    "subscription_interval": "subscriptionInterval",
    "response_validity": "responseValidity",
    "fingerprint_matching_strategy": "fingerprintMatchingStrategy",
}


def _normalize_body(body):
    """Accept both snake_case and camelCase; return camelCase dict."""
    out = {}
    for key, value in body.items():
        out[_FIELD_MAP.get(key, key)] = value
    return out


def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def handler(event, context):
    # --- Auth ---
    caller = validate_api_key(event)
    if caller is None:
        return _response(401, {"error": "Unauthorized. Provide a valid API key."})

    # --- Parse body ---
    try:
        body = json.loads(event.get("body") or "{}")
    except (json.JSONDecodeError, TypeError):
        return _response(400, {"error": "Invalid JSON in request body."})

    body = _normalize_body(body)

    # Fall back to the default product ID from secrets if not provided.
    product_id = body.pop("productId", None)
    if not product_id:
        creds = get_cryptlex_credentials()
        product_id = creds.get("product_id")
    if not product_id:
        return _response(400, {"error": "product_id is required."})

    # --- Create license ---
    try:
        license_data = create_license(product_id, **body)
        logger.info("License created: %s", license_data.get("id", "unknown"))
        return _response(200, license_data)

    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        detail = exc.response.text if exc.response is not None else str(exc)
        logger.error("Cryptlex API error: %s %s", status, detail)
        return _response(status, {"error": "Cryptlex API error", "detail": detail})

    except Exception:
        logger.error("Unhandled error: %s", traceback.format_exc())
        return _response(500, {"error": "Internal server error."})
