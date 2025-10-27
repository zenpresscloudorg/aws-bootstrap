import boto3
import json
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

def load_vars_json(path: str = "vars.json") -> dict:
    """
    Loads the content of vars.json as a dictionary and validates required keys.
    """
    import os
    required_keys = [
        "account_name",
        "account_environment",
        "account_region",
        "vpc_cidr",
        "vpc_ipv6_enable",
        "tailscale_auth_key",
        "hostedzone_public",
        "gh_org",
        "gh_dispatcher_token",
        "gh_runner_token"
    ]
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File '{path}' does not exist.")
    with open(path, "r") as f:
        data = json.load(f)
    missing = [k for k in required_keys if k not in data]
    if missing:
        raise KeyError(f"Missing required keys in vars.json: {missing}")
    return data


def load_aws_key_pair(tag_key: str, tag_value: str, region: str) -> list[dict]:
    """
    Search AWS EC2 key pairs by tag.
    Args:
        tag_key (str): Tag key (example: 'Environment')
        tag_value (str): Tag value (example: 'prod')
        region (str): AWS region
    Returns:
        list[dict]: List of key pairs matching the tag
    """
    ec2 = boto3.client("ec2", region_name=region)
    try:
        response = ec2.describe_key_pairs(
            Filters=[{"Name": f"tag:{tag_key}", "Values": [tag_value]}]
        )
        result = []
        for key_info in response.get("KeyPairs", []):
            result.append({
                "key_name": key_info.get("KeyName"),
                "fingerprint": key_info.get("KeyFingerprint"),
                "key_type": key_info.get("KeyType"),
                "tags": key_info.get("Tags", [])
            })
        return result
    except ClientError as e:
        raise Exception(f"Error searching key pairs by tag: {e}")


def generate_key_pair() -> tuple[str, str]:
    """
    Generates an RSA key pair in SSH format.
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_openssh = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_openssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode('utf-8')
    return json.dumps({
        "private_key": private_openssh,
        "public_key": public_openssh
    }, indent=2)
