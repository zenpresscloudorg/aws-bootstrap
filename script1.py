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

def get_github_oidc_provider_arn(iam):
    """
    Checks if the GitHub OIDC provider exists in the AWS account.
    Returns the ARN if found, otherwise None.
    """
    OIDC_URL = "https://token.actions.githubusercontent.com"
    for p in iam.list_open_id_connect_providers().get("OpenIDConnectProviderList", []):
        arn = p["Arn"]
        d = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        print(d)
    return None

def create_github_oidc_provider(iam):
    """
    Creates the GitHub OIDC provider in the AWS account and returns its ARN.
    """
    OIDC_URL = "https://token.actions.githubusercontent.com"
    CLIENT_ID = "sts.amazonaws.com"
    THUMBPRINT = "6938fd4d98bab03faadb97b34396831e3780aea1"  # GitHub Actions root CA thumbprint
    resp = iam.create_open_id_connect_provider(
        Url=OIDC_URL, ClientIDList=[CLIENT_ID], ThumbprintList=[THUMBPRINT]
    )
    return resp["OpenIDConnectProviderArn"]

# Main

def main():
    arn = get_github_oidc_provider_arn(iam)
    #if arn:
    #    print(f"OIDC provider exists: {arn}")
    #else:
     #   arn = create_github_oidc_provider(iam)
    #    print(f"OIDC provider created: {arn}")

if __name__ == "__main__":
    main()

