import os
import json
import boto3
import botocore
import ipaddress

# Clients

iam = boto3.client("iam")
sts = boto3.client("sts")
s3 = boto3.client("s3")
ec2 = boto3.client("ec2")
session = boto3.session.Session()
import os
import json
import ipaddress

def load_and_validate_vars_json(file):
    """
    Loads and validates vars.json from the same directory as the script.
    Returns the validated dictionary.
    Raises FileNotFoundError or ValueError if something is wrong.
    """
    # Load file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    vars_path = os.path.join(script_dir, file)
    if not os.path.isfile(vars_path):
        raise FileNotFoundError(f"vars.json file not found at: {vars_path}")

    with open(vars_path, "r") as f:
        vars_json = json.load(f)

    # Validate fields
    required_fields = {
        "project_name": str,
        "project_environment": str,
        "vpc_cidr": str,
        "vpc_ipv6": bool,
        "vpc_subnet_private_tskey": str,
        "hostedzones_public": list,
        "hostedzones_private": list,
        "github_account": str,
        "github_repo": str,
    }
    missing = []
    wrong_type = []

    for key, typ in required_fields.items():
        if key not in vars_json:
            missing.append(key)
        elif not isinstance(vars_json[key], typ):
            wrong_type.append(f"{key} (expected {typ.__name__}, got {type(vars_json[key]).__name__})")
    
    if missing:
        raise ValueError(f"Missing required keys in vars.json: {', '.join(missing)}")
    if wrong_type:
        raise ValueError(f"Type error(s) in vars.json: {', '.join(wrong_type)}")
    
    # Check all elements in hostedzones are str
    for list_key in ("hostedzones_public", "hostedzones_private"):
        if any(not isinstance(item, str) for item in vars_json[list_key]):
            raise ValueError(f"All elements in {list_key} must be strings")
    
    # Check vpc_cidr is valid IPv4 CIDR
    try:
        net = ipaddress.IPv4Network(vars_json["vpc_cidr"])
    except Exception as e:
        raise ValueError(f"vpc_cidr is not a valid IPv4 CIDR: {vars_json['vpc_cidr']}. Error: {e}")

    return vars_json

def check_oidc_provider_exists(iam, url):
    """
    Returns True if the GitHub OIDC provider for GitHub Actions exists, False otherwise.
    """
    for p in iam.list_open_id_connect_providers().get("OpenIDConnectProviderList", []):
        arn = p["Arn"]
        response = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        oidc_url = response.get("Url", "")
        if oidc_url == url:
            return True
    return False


def create_oidc_provider(iam, url, clientid, oidc_thumbprint):
    """
    Creates the GitHub OIDC provider in the AWS account and returns its ARN.
    """
    iam.create_open_id_connect_provider(
        Url=url, ClientIDList=[clientid], ThumbprintList=[oidc_thumbprint]
    )

def check_iam_role_exists(iam, role_name):
    """
    Returns True if the IAM role with the given name exists, False otherwise.
    """
    try:
        iam.get_role(RoleName=role_name)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False
    
def get_iam_role_arn(iam, role_name):
    """
    Returns the ARN of the specified IAM role.
    """
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]

def create_iam_role(iam, role_name, trust_policy):
    """
    Creates an IAM role with the specified name and an empty trust policy.
    (You can update the trust policy later.)
    Returns the created role's ARN.
    """
    kwargs = {
        "RoleName": role_name,
        "AssumeRolePolicyDocument": json.dumps(trust_policy)
    }
    resp = iam.create_role(**kwargs)
    return resp["Role"]["Arn"]

def check_iam_policy_exists(iam, policy_name, scope="Local"):
    """
    Returns the ARN if the IAM policy with the given name exists, otherwise returns None.
    scope="Local" (default) busca solo en la cuenta, "AWS" busca policies globales de AWS.
    """
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope=scope):
        for policy in page["Policies"]:
            if policy["PolicyName"] == policy_name:
                return policy["Arn"]
    return None

def create_iam_policy(iam, policy_name, policy_document):
    """
    Creates an IAM policy with the given name and policy document.
    Returns the ARN of the created policy.
    """
    kwargs = {
        "PolicyName": policy_name,
        "PolicyDocument": json.dumps(policy_document)
    }
    resp = iam.create_policy(**kwargs)
    return resp["Policy"]["Arn"]

def attach_policy_to_role(iam, role_name, policy_arn):
    """
    Attaches the specified policy to the given IAM role.
    """
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )

def check_keypair_exists(ec2, name):
    """
    Returns True if the EC2 key pair with the given name exists, False otherwise.
    """
    try:
        response = ec2.describe_key_pairs(KeyNames=[name])
        key_pairs = response.get("KeyPairs", [])
        return any(kp["KeyName"] == name for kp in key_pairs)
    except Exception as e:
        if "InvalidKeyPair.NotFound" in str(e):
            return False
        return False

def create_keypair(ec2, key_name):
    """
    Creates an EC2 key pair with the given name.
    Returns the private key material as a string.
    """
    response = ec2.create_key_pair(KeyName=key_name)
    private_key = response["KeyMaterial"]
    print(f"Key pair '{key_name}' created.")
    return private_key

def check_s3_exists(s3, bucket_name):
    """
    Returns True if the S3 bucket exists, False otherwise.
    """
    try:
        s3.head_bucket(Bucket=bucket_name)
        return True
    except botocore.exceptions.ClientError as e:
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            return False
        elif error_code == 403:
            # Forbidden: bucket exists but no access
            return True
        else:
            # Any other error: treat as not existing, or raise if you prefer
            return False
        
def create_s3(s3, s3_name, s3_policy, account_region):
    """
    Creates an S3 bucket with best-practice security settings, encryption, versioning, and a custom bucket policy.
    """
    s3.create_bucket( Bucket=s3_name, CreateBucketConfiguration={'LocationConstraint': account_region})
    s3.put_public_access_block(
        Bucket=s3_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    s3.put_bucket_encryption(
        Bucket=s3_name,
        ServerSideEncryptionConfiguration={
            'Rules': [
                {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}
            ]
        }
    )
    s3.put_bucket_versioning( Bucket=s3_name, VersioningConfiguration={'Status': 'Enabled'})
    s3.put_bucket_policy(Bucket=s3_name,Policy=json.dumps(s3_policy))

def check_vpc_exists(ec2, vpc_id):
    """
    Returns True if the VPC with the given ID exists, False otherwise.
    """
    try:
        response = ec2.describe_vpcs(VpcIds=[vpc_id])
        return len(response.get("Vpcs", [])) > 0
    except Exception as e:
        # Si el VPC no existe, boto3 lanza ClientError con "InvalidVpcID.NotFound"
        if "InvalidVpcID.NotFound" in str(e):
            return False
        # Otros errores, decide si lanzar o devolver False
        return False
    
def get_vpc_id(ec2, vpc_name):
    """
    Returns the VPC ID for the given Name tag, or None if not found.
    """
    response = ec2.describe_vpcs(
        Filters=[
            {"Name": "tag:Name", "Values": [vpc_name]}
        ]
    )
    vpcs = response.get("Vpcs", [])
    if vpcs:
        return vpcs[0]["VpcId"]
    return None

def create_vpc(ec2, vpc_name, cidr_block, enable_ipv6=False):
    """
    Creates a VPC with the given CIDR and Name tag.
    If enable_ipv6 is True, assigns an Amazon-provided IPv6 block.
    Returns the VPC ID.
    """
    response = ec2.create_vpc(CidrBlock=cidr_block)
    vpc_id = response["Vpc"]["VpcId"]
    ec2.create_tags(  Resources=[vpc_id],Tags=[{"Key": "Name", "Value": vpc_name}])
    if enable_ipv6:
        ec2.assign_ipv6_cidr_block(VpcId=vpc_id)

    return vpc_id


# Main

def main():

    # Vars

    vars_json = load_and_validate_vars_json("vars.json")
    account_id = sts.get_caller_identity()["Account"]
    account_region = session.region_name

    # OIDC Provider

    oidc_url = "token.actions.githubusercontent.com"
    oidc_client_id = "sts.amazonaws.com"
    oidc_thumbprint = "6938fd4d98bab03faadb97b34396831e3780aea1"

    if check_oidc_provider_exists(iam, oidc_url):
        print("OIDC provider already exists, skipping")
    else:
        create_oidc_provider(iam, f"https://{oidc_url}", oidc_client_id, oidc_thumbprint)
        print(f"OIDC provider created")

    # Role

    role_name = f"{vars_json['project_name']}-{vars_json['project_environment']}-role-bootstrap"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": f"arn:aws:iam::{account_id}:oidc-provider/{oidc_url}"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringLike": {
                        "token.actions.githubusercontent.com:sub": f"repo:{vars_json['github_account']}/{vars_json['github_repo']}:*"
                    }
                }
            }
        ]
    }

    if check_iam_role_exists(iam, role_name):
        print(f"IAM role already exists, skipping")
        role_arn = get_iam_role_arn(iam, role_name)
    else:
        role_arn = create_iam_role(iam, role_name, trust_policy)
        print(f"IAM role created")

    # Role policy

    policy_name = f"{vars_json['project_name']}-{vars_json['project_environment']}-policy-bootstrap"
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{vars_json['project_name']}-{vars_json['project_environment']}-s3-*",
                    f"arn:aws:s3:::{vars_json['project_name']}-{vars_json['project_environment']}-s3-*/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": "dynamodb:*",
                "Resource": [
                    f"arn:aws:dynamodb:{account_region}:*:table/{vars_json['project_name']}-{vars_json['project_environment']}-ddb-*"
                ]
            }
        ]
    }

    if check_iam_policy_exists(iam, policy_name):
        print(f"IAM Policy already exists, skipping")
    else:
        policy_arn = create_iam_policy(iam, policy_name, policy_document)
        attach_policy_to_role(iam, role_name, policy_arn)
        print(f"IAM Policy created and attached to Role")

    # S3

    s3_name = f"{vars_json['project_name']}-{vars_json['project_environment']}-s3-bootstrap"
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOnlySpecificRole",
                "Effect": "Allow",
                "Principal": {
                    "AWS": role_arn
                },
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{s3_name}",
                    f"arn:aws:s3:::{s3_name}/*"
                ]
            },
            {
                "Sid": "DenyAllOtherPrincipals",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{s3_name}",
                    f"arn:aws:s3:::{s3_name}/*"
                ],
                "Condition": {
                    "StringNotEquals": {
                        "aws:PrincipalArn": role_arn
                    }
                }
            }
        ]
    }

    if check_s3_exists(s3, s3_name):
        print(f"S3 bucket '{s3_name}' already exists, skipping")
    else:
        create_s3(s3, s3_name, s3_policy, account_region)
        print(f"S3 bucket created")

    # KeyPair

    keypair_name = f"{vars_json['project_name']}-{vars_json['project_environment']}-keypair-bootstrap"

    if check_keypair_exists(ec2, keypair_name):
        print("Key pair exists, skipping")
    else:
        keypair_created = create_keypair(ec2, keypair_name)
        keypair_file = os.path.join(os.path.expanduser("~"), f"{keypair_name}.pem")
        with open(keypair_file, "w") as f:
            f.write(keypair_created)
        print(f"Private key saved to {keypair_file}")

    # VPC

    vpc_name = f"{vars_json['project_name']}-{vars_json['project_environment']}-vpc-bootstrap"

    if check_vpc_exists(ec2, vpc_name):
        print("Vpc exists, skipping")
        vpc_id = get_vpc_id(ec2, vpc_name)
    else:
        vpc_id = create_vpc(ec2, vpc_name, vars_json['vpc_cidr'], vars_json['vpc_ipv6'])
        print(f"Vpc created")

if __name__ == "__main__":
    main()