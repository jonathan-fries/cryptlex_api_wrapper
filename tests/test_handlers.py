"""Unit tests for the Lambda handlers.

Run with: python -m pytest tests/
"""

import json
from unittest.mock import patch

from src.provision_license import handler as provision_handler
from src.offline_activation import handler as offline_handler


# ---- Helpers ----

CRYPTLEX_CREDS = {
    "email": "user@example.com",
    "password": "secret123",
    "accountId": "acct-001",
}


def _api_gateway_event(body=None):
    return {
        "headers": {},
        "body": json.dumps(body) if body else None,
    }


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
    @patch("src.provision_license.authenticate", return_value="fake-token")
    def test_success_creates_license_with_fixed_params(self, mock_auth, mock_create):
        mock_create.return_value = {"id": "lic-123", "key": "ABCD-EFGH"}
        event = _api_gateway_event(CRYPTLEX_CREDS)

        resp = provision_handler(event, None)

        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["id"] == "lic-123"
        assert body["key"] == "ABCD-EFGH"
        mock_auth.assert_called_once_with("user@example.com", "secret123", "acct-001")
        mock_create.assert_called_once_with(
            "fake-token", EXPECTED_PRODUCT_ID, **EXPECTED_LICENSE_DEFAULTS
        )

    @patch("src.provision_license.create_license")
    @patch("src.provision_license.authenticate", return_value="fake-token")
    def test_sends_correct_metadata(self, mock_auth, mock_create):
        mock_create.return_value = {"id": "lic-789"}
        event = _api_gateway_event(CRYPTLEX_CREDS)

        provision_handler(event, None)

        call_kwargs = mock_create.call_args[1]
        assert len(call_kwargs["metadata"]) == 1
        meta = call_kwargs["metadata"][0]
        assert meta["key"] == "LICENSE_VERSION"
        assert meta["value"] == "full"
        assert meta["viewPermissions"] == ["activation"]
        assert meta["visible"] is True

    def test_rejects_missing_credentials(self):
        event = _api_gateway_event({})

        resp = provision_handler(event, None)

        assert resp["statusCode"] == 400
        assert "email" in json.loads(resp["body"])["error"]

    def test_rejects_partial_credentials(self):
        event = _api_gateway_event({"email": "user@example.com"})

        resp = provision_handler(event, None)

        assert resp["statusCode"] == 400

    @patch("src.provision_license.authenticate")
    def test_returns_401_on_bad_cryptlex_credentials(self, mock_auth):
        import requests
        resp_mock = type("MockResp", (), {"status_code": 401, "text": "bad creds"})()
        mock_auth.side_effect = requests.HTTPError(response=resp_mock)
        event = _api_gateway_event(CRYPTLEX_CREDS)

        resp = provision_handler(event, None)

        assert resp["statusCode"] == 401
        assert "authentication failed" in json.loads(resp["body"])["error"].lower()


# ---- Offline Activation Tests ----

class TestOfflineActivation:
    @patch("src.offline_activation.create_offline_activation")
    @patch("src.offline_activation.authenticate", return_value="fake-token")
    def test_success(self, mock_auth, mock_activate):
        mock_activate.return_value = "offline-response-blob"
        event = _api_gateway_event({
            **CRYPTLEX_CREDS,
            "license_id": "lic-123",
            "offline_request": "encrypted-request-data",
            "response_validity": 86400,
        })

        resp = offline_handler(event, None)

        assert resp["statusCode"] == 200
        assert resp["body"] == "offline-response-blob"
        mock_auth.assert_called_once_with("user@example.com", "secret123", "acct-001")
        mock_activate.assert_called_once_with(
            "fake-token", "lic-123", "encrypted-request-data", 86400
        )

    def test_missing_credentials(self):
        event = _api_gateway_event({
            "license_id": "lic-123",
            "offline_request": "data",
            "response_validity": 86400,
        })

        resp = offline_handler(event, None)

        assert resp["statusCode"] == 400
        assert "email" in json.loads(resp["body"])["error"]

    def test_missing_license_id(self):
        event = _api_gateway_event({
            **CRYPTLEX_CREDS,
            "offline_request": "data",
            "response_validity": 86400,
        })

        resp = offline_handler(event, None)

        assert resp["statusCode"] == 400
        assert "license_id" in json.loads(resp["body"])["error"]

    def test_missing_offline_request(self):
        event = _api_gateway_event({
            **CRYPTLEX_CREDS,
            "license_id": "lic-123",
            "response_validity": 86400,
        })

        resp = offline_handler(event, None)

        assert resp["statusCode"] == 400
        assert "offline_request" in json.loads(resp["body"])["error"]

    def test_missing_response_validity(self):
        event = _api_gateway_event({
            **CRYPTLEX_CREDS,
            "license_id": "lic-123",
            "offline_request": "data",
        })

        resp = offline_handler(event, None)

        assert resp["statusCode"] == 400
        assert "response_validity" in json.loads(resp["body"])["error"]

    @patch("src.offline_activation.authenticate")
    def test_returns_401_on_bad_cryptlex_credentials(self, mock_auth):
        import requests
        resp_mock = type("MockResp", (), {"status_code": 401, "text": "bad creds"})()
        mock_auth.side_effect = requests.HTTPError(response=resp_mock)
        event = _api_gateway_event({
            **CRYPTLEX_CREDS,
            "license_id": "lic-123",
            "offline_request": "data",
            "response_validity": 86400,
        })

        resp = offline_handler(event, None)

        assert resp["statusCode"] == 401
        assert "authentication failed" in json.loads(resp["body"])["error"].lower()
