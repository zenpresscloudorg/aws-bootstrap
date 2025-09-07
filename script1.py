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

def load_vars_json():
    """
    Loads var.json from the same directory as the script.
    Returns the parsed dictionary.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    vars_path = os.path.join(script_dir, "var.json")
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

def create_iam_role_with_name_only(iam, role_name):
    """
    Creates an IAM role with the specified name and an empty trust policy.
    (You can update the trust policy later.)
    Returns the created role's ARN.
    """
    empty_trust_policy = {
        "Version": "2012-10-17",
        "Statement": []
    }
    kwargs = {
        "RoleName": role_name,
        "AssumeRolePolicyDocument": json.dumps(empty_trust_policy)
    }
    resp = iam.create_role(**kwargs)
    return resp["Role"]["Arn"]


# Main

def main():

    # Vars

    vars_json = load_vars_json()

    # OIDC Provider

    oidc_url = "token.actions.githubusercontent.com"
    oidc_client_id = "sts.amazonaws.com"
    oidc_thumbprint = "6938fd4d98bab03faadb97b34396831e3780aea1"

    if check_oidc_provider_exists(iam, oidc_url):
        print("OIDC provider for GitHub Actions already exists.")
    else:
        create_oidc_provider(iam, f"https://{oidc_url}", oidc_client_id, oidc_thumbprint)
        print(f"OIDC provider created")


    # Role

    role_name = f"{vars_json.project_name}-{vars_json.project_env}-role-oidc-bootstrap"

    if check_iam_role_exists(iam, role_name):
        print(f"IAM role already exists.")
    else:
        create_iam_role_with_name_only(iam, role_name)
        print(f"IAM role created")


if __name__ == "__main__":
    main()