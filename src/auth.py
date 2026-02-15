import boto3

from src.config import API_KEYS_TABLE

_dynamodb = None


def _get_table():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb.Table(API_KEYS_TABLE)


def validate_api_key(event):
    """Extract and validate the API key from the request.

    Expects the header:  Authorization: Bearer <api-key>

    Returns:
        dict: The item from DynamoDB (contains customer metadata) if valid.
        None: If the key is missing or not found.
    """
    auth_header = (event.get("headers") or {}).get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    api_key = auth_header[len("Bearer "):]
    if not api_key:
        return None

    table = _get_table()
    resp = table.get_item(Key={"api_key": api_key})
    item = resp.get("Item")

    if item and item.get("active", True):
        return item
    return None
