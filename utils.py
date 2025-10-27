import boto3
import json
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os
import random
import string

def load_vars_json(
    path: str = "vars.json"
) -> dict:
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


def validate_account_info(
    account_info: dict
):
    required_keys = ["account", "environment", "region"]
    missing = [k for k in required_keys if k not in account_info]
    if missing:
        raise KeyError(f"Missing required keys in account_info: {missing}")

def get_availability_zones(
    region: str
) -> list:
    """
    Returns a list of availability zones for the given AWS region.
    """
    ec2 = boto3.client("ec2", region_name=region)
    try:
        response = ec2.describe_availability_zones(
            Filters=[{"Name": "region-name", "Values": [region]}]
        )
        return [az["ZoneName"] for az in response["AvailabilityZones"] if az["State"] == "available"]
    except ClientError as e:
        raise Exception(f"Error getting availability zones: {e}")

def load_aws_key_pair(
    account_info: dict,
    product: str,
    usage: str
) -> str | None:
    """
    Finds the first AWS EC2 key pair matching the given tags.
    Returns the key name if found, else None.
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


def generate_key_pair(
) -> tuple[str, str]:
    """
    Generates an RSA key pair in SSH format.
    Returns a JSON string with private and public keys.
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


def create_aws_key_pair(
    account_info: dict,
    product: str,
    usage: str,
    key_material: str = None
) -> str:
    """
    Creates a new AWS EC2 key pair with a random name and required tags.
    Returns the created key name.
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


def load_aws_secret(
    account_info: dict,
    product: str,
    usage: str
) -> dict | None:
    """
    Finds the first AWS Secrets Manager secret matching the given tags.
    Returns a dict with name and arn if found, else None.
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


def create_aws_secret(
    account_info: dict,
    product: str,
    usage: str,
    secret_value: str
) -> dict:
    """
    Creates a new AWS Secrets Manager secret with tags and value.
    The secret name is a random 12-character alphanumeric string.
    Returns a dict with name and arn.
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


def load_aws_vpc(
    account_info: dict,
    product: str,
    usage: str
) -> str | None:
    """
    Finds the first VPC in AWS matching the given tags.
    Returns the vpc_id if found, else None.
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


def create_aws_vpc(
    account_info: dict,
    product: str,
    usage: str,
    cidr_block: str,
    ipv6_enable: bool = False
) -> str:
    """
    Creates a new VPC in AWS with a random name, required tags, and optionally IPv6.
    Returns the created vpc_id.
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


def load_aws_subnet(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str
) -> str | None:
    """
    Finds the first Subnet in AWS matching the given tags and vpc_id.
    Returns a dict with id and cidr if found, else None.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    filters = [
        {"Name": "tag:account", "Values": [account_info["account"]]},
        {"Name": "tag:environment", "Values": [account_info["environment"]]},
        {"Name": "tag:region", "Values": [account_info["region"]]},
        {"Name": "tag:product", "Values": [product]},
        {"Name": "tag:usage", "Values": [usage]},
        {"Name": "vpc-id", "Values": [vpc_id]}
    ]
    try:
        response = ec2.describe_subnets(Filters=filters)
        subnets = response.get("Subnets", [])
        if subnets:
            subnet = subnets[0]
            return {"id": subnet["SubnetId"], "cidr": subnet["CidrBlock"]}
        return None
    except ClientError as e:
        raise Exception(f"Error loading Subnet: {e}")


def create_aws_subnet(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str,
    cidr_block: str,
    availability_zone: str,
    map_public_ip_on_launch: bool
) -> str:
    """
    Creates a new Subnet in AWS with a random name and required tags.
    Returns a dict with id and cidr of the created subnet.
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
    params = {
        "VpcId": vpc_id,
        "CidrBlock": cidr_block,
        "MapPublicIpOnLaunch": map_public_ip_on_launch,
        "AvailabilityZone": availability_zone
    }
    try:
        response = ec2.create_subnet(**params)
        subnet = response["Subnet"]
        subnet_id = subnet["SubnetId"]
        cidr = subnet["CidrBlock"]
        ec2.create_tags(Resources=[subnet_id], Tags=tags)
        return {"id": subnet_id, "cidr": cidr}
    except ClientError as e:
        raise Exception(f"Error creating Subnet: {e}")


def load_aws_security_group(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str
) -> str | None:
    """
    Finds the first Security Group in AWS matching the given tags and vpc_id.
    Returns the security group id if found, else None.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    filters = [
        {"Name": "tag:account", "Values": [account_info["account"]]},
        {"Name": "tag:environment", "Values": [account_info["environment"]]},
        {"Name": "tag:region", "Values": [account_info["region"]]},
        {"Name": "tag:product", "Values": [product]},
        {"Name": "tag:usage", "Values": [usage]},
        {"Name": "vpc-id", "Values": [vpc_id]}
    ]
    try:
        response = ec2.describe_security_groups(Filters=filters)
        sgs = response.get("SecurityGroups", [])
        if sgs:
            sg = sgs[0]
            return sg["GroupId"]
        return None
    except ClientError as e:
        raise Exception(f"Error loading Security Group: {e}")


def create_aws_security_group(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str,
    description: str = "Managed by bootstrap script",
    inbound_rules: list = None,
    outbound_rules: list = None
) -> str:
    """
    Creates a new Security Group in AWS with a random name, required tags, and optional rules.
    Returns the security group id created.
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
        response = ec2.create_security_group(
            GroupName=name,
            Description=description,
            VpcId=vpc_id,
            TagSpecifications=[{
                "ResourceType": "security-group",
                "Tags": tags
            }]
        )
        sg_id = response["GroupId"]
        # Inbound rules
        if inbound_rules:
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=inbound_rules
            )
        # Outbound rules
        if outbound_rules:
            ec2.authorize_security_group_egress(
                GroupId=sg_id,
                IpPermissions=outbound_rules
            )
        else:
            # Default allow all outbound
            ec2.authorize_security_group_egress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            )
        return sg_id
    except ClientError as e:
        raise Exception(f"Error creating Security Group: {e}")

