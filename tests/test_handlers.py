"""Unit tests for the Lambda handlers.

Run with: python -m pytest tests/
"""

import json
from unittest.mock import MagicMock, patch

from src.provision_license import handler as provision_handler
from src.offline_activation import handler as offline_handler


# ---- Helpers ----

def _api_gateway_event(body=None, api_key="test-key-123"):
    return {
        "headers": {"Authorization": f"Bearer {api_key}"},
        "body": json.dumps(body) if body else None,
    }


MOCK_CALLER = {"api_key": "test-key-123", "customer": "Test Corp", "active": True}


# Expected fixed values sent to Cryptlex on every provision call.
EXPECTED_PRODUCT_ID = "1698882a-8ec9-4016-a452-875811d3c953"
EXPECTED_LICENSE_DEFAULTS = {
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


# ---- Provision License Tests ----

class TestProvisionLicense:
    @patch("src.provision_license.create_license")
    @patch("src.provision_license.validate_api_key", return_value=MOCK_CALLER)
    def test_success_creates_license_with_fixed_params(self, mock_auth, mock_create):
        mock_create.return_value = {"id": "lic-123", "key": "ABCD-EFGH"}
        event = _api_gateway_event()

        resp = provision_handler(event, None)

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["id"] == "lic-123"
        assert body["key"] == "ABCD-EFGH"
        mock_create.assert_called_once_with(EXPECTED_PRODUCT_ID, **EXPECTED_LICENSE_DEFAULTS)

    @patch("src.provision_license.create_license")
    @patch("src.provision_license.validate_api_key", return_value=MOCK_CALLER)
    def test_always_uses_fixed_product_id(self, mock_auth, mock_create):
        mock_create.return_value = {"id": "lic-456"}
        event = _api_gateway_event()

        provision_handler(event, None)

        call_args = mock_create.call_args
        assert call_args[0][0] == EXPECTED_PRODUCT_ID

    @patch("src.provision_license.create_license")
    @patch("src.provision_license.validate_api_key", return_value=MOCK_CALLER)
    def test_sends_correct_metadata(self, mock_auth, mock_create):
        mock_create.return_value = {"id": "lic-789"}
        event = _api_gateway_event()

        provision_handler(event, None)

        call_kwargs = mock_create.call_args[1]
        assert len(call_kwargs["metadata"]) == 1
        meta = call_kwargs["metadata"][0]
        assert meta["key"] == "LICENSE_VERSION"
        assert meta["value"] == "full"
        assert meta["viewPermissions"] == ["activation"]
        assert meta["visible"] is True

    @patch("src.provision_license.validate_api_key", return_value=None)
    def test_rejects_bad_api_key(self, mock_auth):
        event = _api_gateway_event()

        resp = provision_handler(event, None)

        assert resp["statusCode"] == 401


# ---- Offline Activation Tests ----

class TestOfflineActivation:
    @patch("src.offline_activation.create_offline_activation")
    @patch("src.offline_activation.validate_api_key", return_value=MOCK_CALLER)
    def test_success(self, mock_auth, mock_activate):
        mock_activate.return_value = "offline-response-blob"
        event = _api_gateway_event({
            "license_id": "lic-123",
            "offline_request": "encrypted-request-data",
            "response_validity": 86400,
        })

        resp = offline_handler(event, None)

        assert resp["statusCode"] == 200
        assert resp["body"] == "offline-response-blob"
        mock_activate.assert_called_once_with("lic-123", "encrypted-request-data", 86400)

    @patch("src.offline_activation.validate_api_key", return_value=MOCK_CALLER)
    def test_missing_license_id(self, mock_auth):
        event = _api_gateway_event({
            "offline_request": "data",
            "response_validity": 86400,
        })

        resp = offline_handler(event, None)

        assert resp["statusCode"] == 400
        assert "license_id" in json.loads(resp["body"])["error"]

    @patch("src.offline_activation.validate_api_key", return_value=MOCK_CALLER)
    def test_missing_offline_request(self, mock_auth):
        event = _api_gateway_event({
            "license_id": "lic-123",
            "response_validity": 86400,
        })

        resp = offline_handler(event, None)

        assert resp["statusCode"] == 400
        assert "offline_request" in json.loads(resp["body"])["error"]

    @patch("src.offline_activation.validate_api_key", return_value=MOCK_CALLER)
    def test_missing_response_validity(self, mock_auth):
        event = _api_gateway_event({
            "license_id": "lic-123",
            "offline_request": "data",
        })

        resp = offline_handler(event, None)

        assert resp["statusCode"] == 400
        assert "response_validity" in json.loads(resp["body"])["error"]

    @patch("src.offline_activation.validate_api_key", return_value=None)
    def test_rejects_bad_api_key(self, mock_auth):
        event = _api_gateway_event({
            "license_id": "lic-123",
            "offline_request": "data",
            "response_validity": 86400,
        })

        resp = offline_handler(event, None)

        assert resp["statusCode"] == 401
