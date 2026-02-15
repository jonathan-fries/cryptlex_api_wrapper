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


# ---- Provision License Tests ----

class TestProvisionLicense:
    @patch("src.provision_license.create_license")
    @patch("src.provision_license.validate_api_key", return_value=MOCK_CALLER)
    def test_success_with_explicit_product_id(self, mock_auth, mock_create):
        mock_create.return_value = {"id": "lic-123", "key": "ABCD-EFGH"}
        event = _api_gateway_event({"product_id": "prod-456"})

        resp = provision_handler(event, None)

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["id"] == "lic-123"
        mock_create.assert_called_once_with("prod-456")

    @patch("src.provision_license.get_cryptlex_credentials")
    @patch("src.provision_license.create_license")
    @patch("src.provision_license.validate_api_key", return_value=MOCK_CALLER)
    def test_falls_back_to_default_product_id(self, mock_auth, mock_create, mock_creds):
        mock_creds.return_value = {"product_id": "default-prod"}
        mock_create.return_value = {"id": "lic-789"}
        event = _api_gateway_event({})

        resp = provision_handler(event, None)

        assert resp["statusCode"] == 200
        mock_create.assert_called_once_with("default-prod")

    @patch("src.provision_license.validate_api_key", return_value=None)
    def test_rejects_bad_api_key(self, mock_auth):
        event = _api_gateway_event({"product_id": "prod-1"})

        resp = provision_handler(event, None)

        assert resp["statusCode"] == 401

    @patch("src.provision_license.validate_api_key", return_value=MOCK_CALLER)
    def test_rejects_invalid_json(self, mock_auth):
        event = {
            "headers": {"Authorization": "Bearer test-key-123"},
            "body": "not json",
        }

        resp = provision_handler(event, None)

        assert resp["statusCode"] == 400

    @patch("src.provision_license.create_license")
    @patch("src.provision_license.validate_api_key", return_value=MOCK_CALLER)
    def test_forwards_optional_params(self, mock_auth, mock_create):
        mock_create.return_value = {"id": "lic-999"}
        event = _api_gateway_event({
            "product_id": "prod-1",
            "allowed_activations": 5,
            "type": "node-locked",
        })

        resp = provision_handler(event, None)

        assert resp["statusCode"] == 200
        mock_create.assert_called_once_with(
            "prod-1", allowedActivations=5, type="node-locked"
        )


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
