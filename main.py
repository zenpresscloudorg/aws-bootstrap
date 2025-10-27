# Imports

import os
import random
import string
import ipaddress
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

key_name = load_aws_key_pair(VAR_ACCOUNT,product=VAR_PRODUCT,usage="main")

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

secret_keypair = load_aws_secret(VAR_ACCOUNT, product=VAR_PRODUCT, usage="keypair")
if not secret_keypair:
    secret_keypair = create_aws_secret(VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage="keypair",
        secret_value=key_material
    )
    print(f"Secret created: {secret_keypair['name']} (ARN: {secret_keypair['arn']})")
else:
    print(f"Secret found: {secret_keypair['name']} (ARN: {secret_keypair['arn']})")

secret_ghdispatcher = load_aws_secret(VAR_ACCOUNT,product=VAR_PRODUCT,usage="ghdispatcher")
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

vpc_id = load_aws_vpc(VAR_ACCOUNT,product=VAR_PRODUCT,usage="main")
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

# Subnet

subnet_public_ids = []
subnet_private_ids = []
vpc_network = ipaddress.IPv4Network(vars_data["vpc_cidr"])
az_list = get_availability_zones(VAR_ACCOUNT["region"])

for i, az in enumerate(az_list):

    # Public subnet
    subnet_id = load_aws_subnet(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage=f"public-{az}",
        vpc_id=vpc_id
    )
    if not subnet_id:
        subnet_id = create_aws_subnet(
            VAR_ACCOUNT,
            product=VAR_PRODUCT,
            usage=f"public-{az}",
            vpc_id=vpc_id,
            cidr_block=str(list(vpc_network.subnets(new_prefix=24))[i*2]),
            availability_zone=az,
            map_public_ip_on_launch=True
        )
        print(f"Public subnet created: {subnet_id} in {az}")
    else:
        print(f"Public subnet found: {subnet_id} in {az}")
    subnet_public_ids.append(subnet_id)

    # Private subnet
    subnet_id = load_aws_subnet(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage=f"private-{az}",
        vpc_id=vpc_id
    )
    if not subnet_id:
        subnet_id = create_aws_subnet(
            VAR_ACCOUNT,
            product=VAR_PRODUCT,
            usage=f"private-{az}",
            vpc_id=vpc_id,
            cidr_block=str(list(vpc_network.subnets(new_prefix=24))[i*2+1]),
            availability_zone=az,
            map_public_ip_on_launch=False
        )
        print(f"Private subnet created: {subnet_id} in {az}")
    else:
        print(f"Private subnet found: {subnet_id} in {az}")
    subnet_private_ids.append(subnet_id)