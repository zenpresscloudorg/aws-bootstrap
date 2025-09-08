import os
import json
import boto3
import botocore

# Clients

iam = boto3.client("iam")
sts = boto3.client("sts")
s3 = boto3.client("s3")
ec2 = boto3.client("ec2")
session = boto3.session.Session()

def load_vars_json(file):
    """
    Loads var.json from the same directory as the script.
    Returns the parsed dictionary.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    vars_path = os.path.join(script_dir, file)
    with open(vars_path, "r") as f:
        vars_data = json.load(f)
    return vars_data

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

def check_s3_bucket_exists(s3, bucket_name):
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
        
def create_s3_bucket(s3, s3_name, s3_policy, account_region):
    """
    Creates an S3 bucket with best-practice security settings, encryption, versioning, and a custom bucket policy.
    """
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


# Main

def main():

    # Vars

    vars_json = load_vars_json("vars.json")

    # Env Vars

    account_id = sts.get_caller_identity()["Account"]
    account_region = session.region_name

    # OIDC Provider

    oidc_url = "token.actions.githubusercontent.com"
    oidc_client_id = "sts.amazonaws.com"
    oidc_thumbprint = "6938fd4d98bab03faadb97b34396831e3780aea1"

    if check_oidc_provider_exists(iam, oidc_url):
        print("OIDC provider already exists.")
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
        print(f"IAM role already exists.")
    else:
        role_arn = create_iam_role(iam, role_name, trust_policy)
        print(f"IAM role created")

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

    if check_s3_bucket_exists(s3, s3_name):
        print(f"S3 bucket '{s3_name}' already exists, skipping")
    else:
        create_s3_bucket(s3, s3_name, s3_policy, account_region)
        print(f"S3 bucket created")

if __name__ == "__main__":
    main()