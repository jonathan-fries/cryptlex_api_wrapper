"""Lambda handler: POST /licenses

Provisions a new Cryptlex license with fixed configuration:
  - productId:          1698882a-8ec9-4016-a452-875811d3c953
  - allowedActivations: 2
  - type:               hosted-floating
  - licenseTemplateId:  2198e1f1-c416-44a2-b3e7-942233ca1d15
  - validity:           31536000  (1 year in seconds)
  - metadata:           LICENSE_VERSION = "full"

Request body (JSON):
    No required fields — all license parameters are set server-side.

Response (200):
    The full license object returned by Cryptlex, including the generated key.
"""

import json
import logging
import traceback

import requests

from src.auth import validate_api_key
from src.cryptlex_client import create_license

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Fixed license configuration — always sent to Cryptlex.
_PRODUCT_ID = "1698882a-8ec9-4016-a452-875811d3c953"

_LICENSE_DEFAULTS = {
    "allowedActivations": 2,
    "type": "hosted-floating",
    "licenseTemplateId": "2198e1f1-c416-44a2-b3e7-942233ca1d15",
    "validity": 31536000,
    "metadata": [
        {
            "key": "LICENSE_VERSION",
            "value": "full",
            "viewPermissions": ["activation"],
            "visible": True,
        }
    ],
}


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

    # --- Create license with fixed params ---
    try:
        license_data = create_license(_PRODUCT_ID, **_LICENSE_DEFAULTS)
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
