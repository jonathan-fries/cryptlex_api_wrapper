"""Utility script to create, list, and revoke API keys in the DynamoDB table.

Usage:
    python scripts/manage_api_keys.py create --customer "Acme Corp"
    python scripts/manage_api_keys.py list
    python scripts/manage_api_keys.py revoke --key <api-key>
"""

import argparse
import secrets
import sys
from datetime import datetime, timezone

import boto3

TABLE_NAME = "cryptlex-wrapper-api-keys"


def get_table():
    dynamodb = boto3.resource("dynamodb")
    return dynamodb.Table(TABLE_NAME)


def create_key(customer_name):
    table = get_table()
    api_key = secrets.token_urlsafe(32)
    table.put_item(
        Item={
            "api_key": api_key,
            "customer": customer_name,
            "active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    print(f"Created API key for '{customer_name}':")
    print(f"  {api_key}")
    print("Store this key securely — it cannot be retrieved later.")


def list_keys():
    table = get_table()
    resp = table.scan()
    items = resp.get("Items", [])
    if not items:
        print("No API keys found.")
        return
    for item in items:
        status = "active" if item.get("active", True) else "REVOKED"
        print(f"  [{status}] {item['api_key'][:8]}... - {item.get('customer', 'unknown')} ({item.get('created_at', '')})")


def revoke_key(api_key):
    table = get_table()
    table.update_item(
        Key={"api_key": api_key},
        UpdateExpression="SET active = :val",
        ExpressionAttributeValues={":val": False},
    )
    print(f"Revoked API key: {api_key[:8]}...")


def main():
    parser = argparse.ArgumentParser(description="Manage Cryptlex wrapper API keys")
    sub = parser.add_subparsers(dest="command")

    create_parser = sub.add_parser("create", help="Create a new API key")
    create_parser.add_argument("--customer", required=True, help="Customer name")

    sub.add_parser("list", help="List all API keys")

    revoke_parser = sub.add_parser("revoke", help="Revoke an API key")
    revoke_parser.add_argument("--key", required=True, help="The API key to revoke")

    args = parser.parse_args()

    if args.command == "create":
        create_key(args.customer)
    elif args.command == "list":
        list_keys()
    elif args.command == "revoke":
        revoke_key(args.key)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
