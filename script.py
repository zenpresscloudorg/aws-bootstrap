import os
import json
import sys
import ipaddress
import boto3
from urllib.parse import urlparse

# Clients

iam = boto3.client("iam")
sts = boto3.client("sts")
session = boto3.session.Session()
s3 = boto3.client("s3")
ec2 = boto3.client("ec2")

# Load vars

with open("aws-bootstrap/vars.json") as f:
    vars = json.load(f)

# Validation

REQUIRED_VARS = [
    "project_name",
    "project_environment",
    "vpc_cidr",
    "vpc_ipv6",
    "hostedzones_public",
    "hostedzones_private",
    "vpc_subnet_private_tskey",
    "github_account",
    "github_repo"
]

ARRAY_VARS = [
    "hostedzones_public",
    "hostedzones_private"
]

missing = [var for var in REQUIRED_VARS if var not in vars]
wrong_type = [var for var in ARRAY_VARS if var in vars and not isinstance(vars[var], list)]

if missing or wrong_type:
    if missing:
        print(f"Missing required variables in vars.json: {', '.join(missing)}", file=sys.stderr)
    if wrong_type:
        print(f"These variables must be arrays (even if empty): {', '.join(wrong_type)}", file=sys.stderr)
    sys.exit(1)

if "/" not in vars["vpc_cidr"]:
    print("vpc_cidr must include a subnet mask (e.g., 10.0.0.0/16)", file=sys.stderr)
    sys.exit(1)

try:
    ipaddress.IPv4Network(vars["vpc_cidr"])
except Exception:
    print("vpc_cidr must be a valid IPv4 CIDR (e.g., 10.0.0.0/16)", file=sys.stderr)
    sys.exit(1)

# Variables

account_id = sts.get_caller_identity()["Account"]
account_region = session.region_name
account_azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]]
project_name = vars["project_name"]
project_env = vars["project_environment"]

### MOVER

hostedzones_public = vars["hostedzones_public"]
hostedzones_private = vars["hostedzones_private"]
vpc_subnet_private_tskey = vars["vpc_subnet_private_tskey"]
instance_natgw_name = f"{project_name}-{project_env}-ec2-natgw-bootstrap"
public_rt_name = f"{project_name}-{project_env}-rt-public-bootstrap"
private_rt_name = f"{project_name}-{project_env}-rt-private-bootstrap"

# OIDC Github

OIDC_URL = "https://token.actions.githubusercontent.com"
CLIENT_ID = "sts.amazonaws.com"
THUMBPRINT = "6938fd4d98bab03faadb97b34396831e3780aea1"
oicd_arn = None
def canonical_url(url):
    url = url.strip().lower().rstrip("/")
    if url.startswith("http"):
        url = urlparse(url).netloc
    return url

for list_oicd in iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]:
    list_oicd_arn = list_oicd["Arn"]
    details = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=list_oicd_arn)
    provider_url = canonical_url(details.get("Url", ""))
    if provider_url == canonical_url(OIDC_URL):
        oicd_arn = list_oicd_arn
        break

if oicd_arn:
    print("OIDC provider already exists")
else:
    print("OIDC provider not found, creando uno nuevo...")
    iam.create_open_id_connect_provider(
        Url=OIDC_URL,
        ClientIDList=[CLIENT_ID],
        ThumbprintList=[THUMBPRINT]
    )
    print("OIDC provider created")

# OICD Role

role_name = f"{project_name}-{project_env}-role-oidc-bootstrap"
policy_name = f"{project_name}-{project_env}-policy-oidc-bootstrap"
github_account = vars["github_account"]
github_repo = vars["github_repo"]
list_roles = iam.list_roles()["Roles"]
role_names = [r["RoleName"] for r in list_roles]
role_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": [
                f"arn:aws:s3:::{project_name}-s3-{project_env}-*",
                f"arn:aws:s3:::{project_name}-s3-{project_env}-*/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": "dynamodb:*",
            "Resource": [
                f"arn:aws:dynamodb:{account_region}:*:table/{project_name}-ddb-{project_env}-*"
            ]
        }
    ]
}
trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": f"arn:aws:iam::{account_id}:oidc-provider/token.actions.githubusercontent.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": f"repo:{github_account}/{github_repo}:*"
                }
            }
        }
    ]
}

if role_name in role_names:
    for r in list_roles:
        if r["RoleName"] == role_name:
            role_arn = r["Arn"]
            break
    print("Role exists, skipping creation and policy update")
else:
    role_data=iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role_data["Role"]["Arn"]
    print("Role created")

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(role_policy)
    )

    print(f"Inline policy attached to role {role_name}.")

# S3 Bucket

s3_name = f"{project_name}-{project_env}-s3-bootstrap"
list_buckets = [b['Name'] for b in s3.list_buckets()["Buckets"]]
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


if s3_name in list_buckets:
    print("Bucket exists, skipping")
else:
    s3.create_bucket(
        Bucket=s3_name,
        CreateBucketConfiguration={'LocationConstraint': account_region}
    )
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
    s3.put_bucket_versioning(
        Bucket=s3_name,
        VersioningConfiguration={'Status': 'Enabled'}
    )
    s3.put_bucket_policy(
        Bucket=s3_name,
        Policy=json.dumps(s3_policy)
    )
    print("Bucket created")

# Keypair

keypair_name = f"{project_name}-{project_env}-keypair-bootstrap"
keypair_file = os.path.expandvars(f"$HOME/{keypair_name}.pem")
keypair_names = [k["KeyName"] for k in ec2.describe_key_pairs()["KeyPairs"]]

if keypair_name in keypair_names:
    print("Key pair exists, skipping")
else:
    create_keypair = ec2.create_key_pair(KeyName=keypair_name)
    key_material = create_keypair["KeyMaterial"]
    with open(keypair_file, "w") as f:
        f.write(key_material)
    print(f"Key pair created and saved as {keypair_file}")

# VPC

vpc_name = f"{project_name}-{project_env}-vpc-bootstrap"
vpc_cidr = vars["vpc_cidr"]
vpc_ipv6 = vars["vpc_ipv6"]
vpc_network = ipaddress.ip_network(vpc_cidr)
list_vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [vpc_name]}])
vpc_names = list_vpcs.get("Vpcs", [])

# VPC

vpc_name = f"{project_name}-{project_env}-vpc-bootstrap"
vpc_cidr = vars["vpc_cidr"]
vpc_ipv6 = vars["vpc_ipv6"]
vpc_network = ipaddress.ip_network(vpc_cidr)
list_vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [vpc_name]}])
vpc_names = list_vpcs.get("Vpcs", [])

if vpc_names:
    print(f"VPC exists, skipping creation")
    vpc_id = vpc_names[0]["VpcId"]
else:
    create_vpc = ec2.create_vpc(CidrBlock=vpc_cidr)
    vpc_id = create_vpc["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": vpc_name}])
    print(f"VPC created: {vpc_id}")
    if str(vpc_ipv6).lower() == "true":
        ipv6_assoc = ec2.associate_vpc_cidr_block(
            VpcId=vpc_id,
            AmazonProvidedIpv6CidrBlock=True
        )
        assoc = ipv6_assoc.get("Ipv6CidrBlockAssociation", {})
        ipv6_cidr = assoc.get("Ipv6CidrBlock")
        state = assoc.get("Ipv6CidrBlockState", {}).get("State", "unknown")
        print(f"IPv6 enabled for VPC")
    else:
        print("IPv6 not enabled for VPC.")

