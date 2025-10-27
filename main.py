# Imports

import os
import random
import string
from utils import *

# Vars

try:
    vars_data = load_vars_json()
    VAR_ACCOUNT = {
        "account": vars_data["account_name"],
        "environment": vars_data["account_environment"],
        "region": vars_data["account_region"]
    }
    VAR_PRODUCT = "bootstrap"
except Exception as e:
    print(f"Error loading vars.json: {e}")
    exit(1)

# SSH Key

key_name = load_aws_key_pair(
    VAR_ACCOUNT,
    product=VAR_PRODUCT,
    usage="main"
)

if not key_name:
    key_material = generate_key_pair()
    key_name = create_aws_key_pair(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage="main",
        key_material=key_material
    )

print(key_name)

# Secrets

secret_keypair = load_aws_secret(
    VAR_ACCOUNT,
    product=VAR_PRODUCT,
    usage="keypair"
)
if not secret_keypair:
    secret_keypair = create_aws_secret(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage="keypair",
        secret_value=key_material
    )
    print(f"Secret created: {secret_keypair['name']} (ARN: {secret_keypair['arn']})")
else:
    print(f"Secret found: {secret_keypair['name']} (ARN: {secret_keypair['arn']})")

secret_ghdispatcher = load_aws_secret(
    VAR_ACCOUNT,
    product=VAR_PRODUCT,
    usage="ghdispatcher"
)
if not secret_ghdispatcher:
    secret_ghdispatcher = create_aws_secret(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage="ghdispatcher",
        secret_value=''.join(random.choices(string.ascii_letters + string.digits, k=12))
    )
    print(f"Secret created: {secret_ghdispatcher['name']} (ARN: {secret_ghdispatcher['arn']})")
else:
    print(f"Secret found: {secret_ghdispatcher['name']} (ARN: {secret_ghdispatcher['arn']})")

# VPC

vpc_id = load_aws_vpc(
    VAR_ACCOUNT,
    product=VAR_PRODUCT,
    usage="main"
)
if not vpc_id:
    vpc_id = create_aws_vpc(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage="main",
        cidr_block=vars_data["vpc_cidr"],
        ipv6_enable=vars_data.get("vpc_ipv6_enable", False)
    )
    print(f"VPC created: {vpc_id}")
else:
    print(f"VPC found: {vpc_id}")