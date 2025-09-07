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

def list_oidc_provider(iam):
    """
    Returns True if the GitHub OIDC provider for GitHub Actions exists, False otherwise.
    """
    for p in iam.list_open_id_connect_providers().get("OpenIDConnectProviderList", []):
        arn = p["Arn"]
        d = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        url = d.get("Url", "")
        # Direct string edit: remove "https://" from url
        if url == "token.actions.githubusercontent.com":
            return True
    return False


def create_oidc_provider(iam):
    """
    Creates the GitHub OIDC provider in the AWS account and returns its ARN.
    """
    OIDC_URL = "https://token.actions.githubusercontent.com"
    CLIENT_ID = "sts.amazonaws.com"
    THUMBPRINT = "6938fd4d98bab03faadb97b34396831e3780aea1"  # GitHub Actions root CA thumbprint
    iam.create_open_id_connect_provider(
        Url=OIDC_URL, ClientIDList=[CLIENT_ID], ThumbprintList=[THUMBPRINT]
    )

# Main

def main():
    if list_oidc_provider(iam):
        print("OIDC provider for GitHub Actions already exists.")
    else:
        create_oidc_provider(iam)
        print(f"OIDC provider created")

if __name__ == "__main__":
    main()