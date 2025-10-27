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
    VAR_INSTANCE_MODEL = "t4g.nano"
    VAR_INSTANCE_AMI = "ami-0cd0767d8ed6ad0a9"
    VAR_INSTANCE_DISK_SIZE = "8"
    VAR_INSTANCE_DISK_TYPE = "gp3"
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

vpc_network = ipaddress.IPv4Network(vars_data["vpc_cidr"])
az_list = get_availability_zones(VAR_ACCOUNT["region"])
for i, az in enumerate(az_list):

    # Public subnet
    subnet_public = load_aws_subnet(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage=f"public-{az}",
        vpc_id=vpc_id
    )
    if not subnet_public:
        subnet_public = create_aws_subnet(
            VAR_ACCOUNT,
            product=VAR_PRODUCT,
            usage=f"public-{az}",
            vpc_id=vpc_id,
            cidr_block=str(list(vpc_network.subnets(new_prefix=24))[i*2]),
            availability_zone=az,
            map_public_ip_on_launch=True
        )
        print(f"Public subnet created: {subnet_public['id']} in {az}")
    else:
        print(f"Public subnet found: {subnet_public['id']} in {az}")
    subnet_public.append(subnet_public)

    # Private subnet
    subnet_private = load_aws_subnet(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage=f"private-{az}",
        vpc_id=vpc_id
    )
    if not subnet_private:
        subnet_private = create_aws_subnet(
            VAR_ACCOUNT,
            product=VAR_PRODUCT,
            usage=f"private-{az}",
            vpc_id=vpc_id,
            cidr_block=str(list(vpc_network.subnets(new_prefix=24))[i*2+1]),
            availability_zone=az,
            map_public_ip_on_launch=False
        )
        print(f"Private subnet created: {subnet_private['id']} in {az}")
    else:
        print(f"Private subnet found: {subnet_private['id']} in {az}")
    subnet_private.append(subnet_private)

# Security Group

sg_test_id = load_aws_security_group(VAR_ACCOUNT,product=VAR_PRODUCT,usage="test",vpc_id=vpc_id)
sg_natgw_id = load_aws_security_group(VAR_ACCOUNT,product=VAR_PRODUCT,usage="natgw",vpc_id=vpc_id)
sg_ghrunner_id = load_aws_security_group(VAR_ACCOUNT,product=VAR_PRODUCT,usage="ghrunner",vpc_id=vpc_id)

if not sg_test_id:
    sg_test_id = create_aws_security_group(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage="test",
        vpc_id=vpc_id,
        description="Test security group",
        inbound_rules=[{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }]
    )
    print(f"Security Group created: {sg_test_id}")
else:
    print(f"Security Group found: {sg_test_id}")

if not sg_natgw_id:
    sg_natgw_id = create_aws_security_group(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage="natgw",
        vpc_id=vpc_id,
        description="ec2_natgw",
        inbound_rules=[{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": subnet["cidr"]} for subnet in subnet_private]
        }],
    )
    print(f"Security Group NATGW created: {sg_natgw_id}")
else:
    print(f"Security Group NATGW found: {sg_natgw_id}")

if not sg_ghrunner_id:
    sg_ghrunner_id = create_aws_security_group(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage="ghrunner",
        vpc_id=vpc_id,
        description="ec2_ghrunner",
    )
    print(f"Security Group GHRUNNER created: {sg_ghrunner_id}")
else:
    print(f"Security Group GHRUNNER found: {sg_ghrunner_id}")

# Natgw Instance

instance_natgw = load_aws_instance(VAR_ACCOUNT,product=VAR_PRODUCT,usage="natgw")
if not instance_natgw:
    instance_natgw = create_aws_instance(
        VAR_ACCOUNT,
        product=VAR_PRODUCT,
        usage="natgw",
        ami=VAR_INSTANCE_AMI,
        instance_type=VAR_INSTANCE_MODEL,
        disk_type=VAR_INSTANCE_DISK_TYPE,
        disk_size=VAR_INSTANCE_DISK_SIZE,
        sg_id=sg_natgw_id,
        subnet_id=subnet_private[0]["id"],
        key_name=key_name,
        delete_on_termination=True,
        userdata=vars_data.get("natgw_userdata")
    )
    print(f"Instancia NATGW creada: {instance_natgw['id']} (estado: {instance_natgw['state']})")
else:
    print(f"Instancia NATGW encontrada: {instance_natgw['id']} (estado: {instance_natgw['state']})")