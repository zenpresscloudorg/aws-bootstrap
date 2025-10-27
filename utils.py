import boto3
import json
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os
import random
import string

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


def validate_account_info(account_info: dict):
    required_keys = ["account", "environment", "region"]
    missing = [k for k in required_keys if k not in account_info]
    if missing:
        raise KeyError(f"Missing required keys in account_info: {missing}")


def load_aws_key_pair(account_info: dict, product: str, usage: str) -> str | None:
    """
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    filters = [
        {"Name": "tag:account", "Values": [account_info["account"]]},
        {"Name": "tag:environment", "Values": [account_info["environment"]]},
        {"Name": "tag:region", "Values": [account_info["region"]]},
        {"Name": "tag:product", "Values": [product]},
        {"Name": "tag:usage", "Values": [usage]}
    ]
    try:
        response = ec2.describe_key_pairs(Filters=filters)
        keypairs = response.get("KeyPairs", [])
        if keypairs:
            return keypairs[0].get("KeyName")
        return None
    except ClientError as e:
        raise Exception(f"Error searching key pairs by tags: {e}")


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


def create_aws_key_pair(account_info: dict, product: str, usage: str) -> str:
    """
    Creates a new AWS EC2 key pair with random name and required tags.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    tags = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage}
    ]
    try:
        ec2.create_key_pair(
            KeyName=name,
            TagSpecifications=[{
                "ResourceType": "key-pair",
                "Tags": tags
            }]
        )
        return name
    except ClientError as e:
        raise Exception(f"Error creating key pair: {e}")


def load_aws_secret(account_info: dict, product: str, usage: str) -> dict | None:
    """
    Busca el primer secreto en AWS Secrets Manager que tenga los tags correctos.
    Retorna un dict con name y arn si lo encuentra, si no None.
    """
    validate_account_info(account_info)
    client = boto3.client("secretsmanager", region_name=account_info["region"])
    filters = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage}
    ]
    try:
        paginator = client.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                secret_tags = {tag["Key"]: tag["Value"] for tag in secret.get("Tags", [])}
                if all(tag["Value"] == secret_tags.get(tag["Key"]) for tag in filters):
                    return {
                        "name": secret.get("Name"),
                        "arn": secret.get("ARN")
                    }
        return None
    except ClientError as e:
        raise Exception(f"Error loading secret: {e}")


def create_aws_secret(account_info: dict, product: str, usage: str, secret_value: str) -> dict:
    """
    Creates a new AWS Secrets Manager secret with tags and value.
    The secret name is a random 12-character alphanumeric string.
    Returns a dict with secret_name and secret_arn.
    """
    validate_account_info(account_info)
    client = boto3.client("secretsmanager", region_name=account_info["region"])
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    tags = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage}
    ]
    try:
        response = client.create_secret(
            Name=name,
            SecretString=secret_value,
            Tags=tags
        )
        return {
            "name": name,
            "arn": response["ARN"]
        }
    except ClientError as e:
        raise Exception(f"Error creating secret: {e}")


def load_aws_vpc(account_info: dict, product: str, usage: str) -> dict | None:
    """
    Busca la primera VPC en AWS que tenga los tags correctos.
    Retorna un dict con vpc_id y arn si la encuentra, si no None.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    filters = [
        {"Name": "tag:account", "Values": [account_info["account"]]},
        {"Name": "tag:environment", "Values": [account_info["environment"]]},
        {"Name": "tag:region", "Values": [account_info["region"]]},
        {"Name": "tag:product", "Values": [product]},
        {"Name": "tag:usage", "Values": [usage]}
    ]
    try:
        response = ec2.describe_vpcs(Filters=filters)
        vpcs = response.get("Vpcs", [])
        if vpcs:
            vpc = vpcs[0]
            return vpc["VpcId"]
        return None
    except ClientError as e:
        raise Exception(f"Error loading VPC: {e}")


def create_aws_vpc(account_info: dict, product: str, usage: str, cidr_block: str, ipv6_enable: bool = False) -> str:
    """
    Crea una nueva VPC en AWS con nombre aleatorio, los tags requeridos y opcionalmente IPv6.
    Retorna el vpc_id creado.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    tags = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage},
        {"Key": "Name", "Value": name}
    ]
    try:
        response = ec2.create_vpc(CidrBlock=cidr_block)
        vpc_id = response["Vpc"]["VpcId"]
        ec2.create_tags(Resources=[vpc_id], Tags=tags)
        if ipv6_enable:
            ec2.assign_ipv6_cidr_block(VpcId=vpc_id, AmazonProvidedIpv6CidrBlock=True)
        return vpc_id
    except ClientError as e:
        raise Exception(f"Error creating VPC: {e}")