# Imports

import os
import json
import boto3
import botocore
import time
import ipaddress

# Clients

iam = boto3.client("iam")
sts = boto3.client("sts")
s3 = boto3.client("s3")
ec2 = boto3.client("ec2")
route53 = boto3.client("route53")
session = boto3.session.Session()

# Functions

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

def get_available_azs(ec2):
    """
    Returns a list of available Availability Zones names in the region.
    """
    response = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )
    return [az["ZoneName"] for az in response["AvailabilityZones"]]

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
    time.sleep(10)
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

def check_vpc_exists(ec2, vpc_name):
    """
    Returns True if the VPC with the given name exists, False otherwise.
    """
    response = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [vpc_name]}])
    vpcs = response.get("Vpcs", [])
    if vpcs:
        return vpcs[0]["VpcId"]
    return None
    
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
        ec2.associate_vpc_cidr_block(VpcId=vpc_id, AmazonProvidedIpv6CidrBlock=True)
        print(f"IPv6 enabled for VPC")
    return vpc_id

def check_sg_exists(ec2, vpc_id, sg_name):
    """
    Devuelve True si existe un Security Group con ese nombre en la VPC, False si no existe.
    """
    response = ec2.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [sg_name]},
            {"Name": "vpc-id", "Values": [vpc_id]}
        ]
    )
    return len(response.get("SecurityGroups", [])) > 0

def get_sg_id(ec2, vpc_id, sg_name):
    """
    Devuelve el GroupId del Security Group con ese nombre en la VPC, o None si no existe.
    """
    response = ec2.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [sg_name]},
            {"Name": "vpc-id", "Values": [vpc_id]}
        ]
    )
    groups = response.get("SecurityGroups", [])
    if groups:
        return groups[0]["GroupId"]
    return None


def create_sg(ec2, vpc_id, sg_name, description):
    """
    Crea un security group en la VPC indicada con el nombre y descripción dados.
    Devuelve el SecurityGroupId creado.
    """
    response = ec2.create_security_group(
        GroupName=sg_name,
        VpcId=vpc_id,
        Description=description
    )
    sg_id = response['GroupId']
    # Añade el tag Name para facilitar búsqueda en consola
    ec2.create_tags(
        Resources=[sg_id],
        Tags=[{"Key": "Name", "Value": sg_name}]
    )
    return sg_id

def create_sg_inbound_rule(ec2, sg_id, protocol, from_port=None, to_port=None, cidr="0.0.0.0/0"):
    """
    Añade una regla inbound al Security Group.
    Si protocol == '-1' (ALL), ignora from_port y to_port.
    """
    perm = {
        'IpProtocol': protocol,
        'IpRanges': [{'CidrIp': cidr}]
    }
    if protocol != "-1":
        perm['FromPort'] = from_port
        perm['ToPort'] = to_port

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[perm]
    )


def check_subnet_exists(ec2, subnet_name):
    """
    Returns True if a subnet with the given Name tag exists, False otherwise.
    """
    response = ec2.describe_subnets(
        Filters=[{"Name": "tag:Name", "Values": [subnet_name]}]
    )
    return len(response.get("Subnets", [])) > 0

def get_subnet_by_name(ec2, subnet_name):
    """
    Returns the subnet dict for the given Name tag, or None if not found.
    """
    response = ec2.describe_subnets(
        Filters=[{"Name": "tag:Name", "Values": [subnet_name]}]
    )
    subnets = response.get("Subnets", [])
    if subnets:
        return subnets[0]
    return None

def create_subnet(ec2, subnet_name, vpc_id, cidr_block, az):
    """
    Creates a subnet in the given VPC and AZ with the specified CIDR.
    Assigns the Name tag.
    Returns the Subnet ID.
    """
    response = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr_block,
        AvailabilityZone=az
    )
    subnet_id = response["Subnet"]["SubnetId"]
    ec2.create_tags( Resources=[subnet_id], Tags=[{"Key": "Name", "Value": subnet_name}])
    return subnet_id

def check_rt_exists(ec2, vpc_id, rt_name):
    """
    Devuelve True si existe una Route Table con ese nombre en la VPC, False si no existe.
    Busca por tag:Name y VPC.
    """
    response = ec2.describe_route_tables(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "tag:Name", "Values": [rt_name]}
        ]
    )
    return len(response.get("RouteTables", [])) > 0

def create_rt(ec2, vpc_id, rt_name):
    """
    Crea una route table en la VPC indicada y la etiqueta con Name=rt_name.
    Devuelve el RouteTableId creado.
    """
    response = ec2.create_route_table(VpcId=vpc_id)
    rt_id = response["RouteTable"]["RouteTableId"]
    ec2.create_tags(
        Resources=[rt_id],
        Tags=[{"Key": "Name", "Value": rt_name}]
    )
    return rt_id

def create_route(ec2, rt_id, destination_cidr, target_type, target_id):
    """
    Crea una ruta en la Route Table (rt_id).
    - destination_cidr: destino de la ruta, ej: '0.0.0.0/0'
    - target_type: uno de 'GatewayId', 'NatGatewayId', 'InstanceId', etc.
    - target_id: el id del recurso de destino (ej: IGW, NATGW, EC2 Instance, etc.)
    """
    route_args = {
        'RouteTableId': rt_id,
        'DestinationCidrBlock': destination_cidr,
        target_type: target_id
    }
    ec2.create_route(**route_args)


def associate_rt_to_subnet(ec2, subnet_id, rt_id):
    """
    Asocia una subnet (subnet_id) a una route table (rt_id).
    Devuelve el AssociationId.
    """
    response = ec2.associate_route_table(
        SubnetId=subnet_id,
        RouteTableId=rt_id
    )

def check_igw_exists(ec2, igw_name):
    """
    Devuelve True si existe un Internet Gateway con el tag Name indicado, False si no existe.
    """
    response = ec2.describe_internet_gateways(
        Filters=[
            {"Name": "tag:Name", "Values": [igw_name]}
        ]
    )
    return len(response.get("InternetGateways", [])) > 0

def get_igw_id(ec2, igw_name):
    """
    Devuelve el InternetGatewayId del IGW con el tag Name indicado, o None si no existe.
    """
    response = ec2.describe_internet_gateways(
        Filters=[
            {"Name": "tag:Name", "Values": [igw_name]}
        ]
    )
    igws = response.get("InternetGateways", [])
    if igws:
        return igws[0]["InternetGatewayId"]
    return None

def create_igw(ec2, igw_name):
    """
    Crea un Internet Gateway y lo etiqueta con Name=igw_name.
    Devuelve el InternetGatewayId creado.
    """
    response = ec2.create_internet_gateway()
    igw_id = response["InternetGateway"]["InternetGatewayId"]
    ec2.create_tags(
        Resources=[igw_id],
        Tags=[{"Key": "Name", "Value": igw_name}]
    )
    print(f"Internet Gateway '{igw_name}' creado. ID: {igw_id}")
    return igw_id

def attach_igw_to_vpc(ec2, igw_id, vpc_id):
    """
    Asocia (adjunta) el IGW indicado a la VPC.
    """
    ec2.attach_internet_gateway(
        InternetGatewayId=igw_id,
        VpcId=vpc_id
    )

def create_eip(ec2):
    """
    Crea una Elastic IP y devuelve su AllocationId.
    """
    response = ec2.allocate_address(Domain="vpc")
    allocation_id = response["AllocationId"]
    return allocation_id

def associate_eip_to_instance(ec2, allocation_id, instance_id):
    """
    Asocia una Elastic IP (EIP) a una instancia EC2.
    """
    ec2.associate_address(
        AllocationId=allocation_id,
        InstanceId=instance_id
    )

def check_instance_exists(ec2, instance_name):
    """
    Devuelve True si existe al menos una instancia EC2 con el tag Name=instance_name, False si no.
    """
    response = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": [instance_name]},
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}
        ]
    )
    reservations = response.get("Reservations", [])
    instances = [i for r in reservations for i in r.get("Instances", [])]
    return len(instances) > 0

def get_instance_id_by_name(ec2, instance_name):
    """
    Devuelve el InstanceId de la primera instancia con el tag Name=instance_name, o None si no existe.
    """
    response = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": [instance_name]},
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}
        ]
    )
    reservations = response.get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            return instance["InstanceId"]
    return None

def create_ec2_instance(ec2, instance_name, ebs_name, instance_type,ami_id, key_name, subnet_id, sg_id, user_data=None):
    """
    Lanza una instancia EC2 y espera a que esté en estado 'running'.
    Devuelve el InstanceId creado.
    """
    block_device_mappings = [{
        'DeviceName': '/dev/xvda',
        'Ebs': {
            'DeleteOnTermination': True,
        }
    }]

    launch_args = {
        "ImageId": ami_id,
        "InstanceType": instance_type,
        "KeyName": key_name,
        "SubnetId": subnet_id,
        "SecurityGroupIds": [sg_id] if isinstance(sg_id, str) else sg_id,
        "BlockDeviceMappings": block_device_mappings,
        "TagSpecifications": [
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": instance_name}]
            },
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Name", "Value": ebs_name}]
            }
        ],
        "MinCount": 1,
        "MaxCount": 1
    }
    if user_data:
        launch_args["UserData"] = user_data

    response = ec2.run_instances(**launch_args)
    instance_id = response["Instances"][0]["InstanceId"]
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    return instance_id

def disable_source_dest_check(ec2, instance_id):
    """
    Desactiva el source/destination check en una instancia EC2.
    Esto es necesario por ejemplo para instancias NAT.
    """
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        SourceDestCheck={'Value': False}
    )

def check_hosted_zone_exists(route53, zone_name):
    """
    Comprueba si existe una hosted zone (pública o privada) con ese nombre exacto (debe terminar en '.').
    Devuelve (True, zone_id) si existe, (False, None) si no existe.
    """
    paginator = route53.get_paginator("list_hosted_zones")
    for page in paginator.paginate():
        for zone in page["HostedZones"]:
            # Route53 guarda los nombres con '.' al final
            if zone["Name"] == zone_name:
                return True
    return False

def get_hosted_zone_id_and_dns(route53, zone_name):
    """
    Devuelve el zone_id y, si la zona es pública, una lista de nameservers.
    Si es privada, la lista de nameservers será None.
    - zone_name: debe terminar en '.'
    """
    if not zone_name.endswith('.'):
        zone_name += '.'

    paginator = route53.get_paginator("list_hosted_zones")
    for page in paginator.paginate():
        for zone in page["HostedZones"]:
            if zone["Name"] == zone_name:
                zone_id = zone["Id"]
                # Saber si es pública o privada
                is_private = zone.get("Config", {}).get("PrivateZone", False)
                if not is_private:
                    # Buscar los NS
                    resp = route53.get_hosted_zone(Id=zone_id)
                    ns_list = []
                    # Extraer los NS records
                    for rr in resp["DelegationSet"]["NameServers"]:
                        ns_list.append(rr)
                    return zone_id, ns_list
                else:
                    return zone_id, None
    return None, None  # No encontrada

def create_hosted_zone(route53, zone_name, is_private=False, vpc_id=None, vpc_region=None, comment="Created by script"):
    """
    Crea una hosted zone en Route53.
    - zone_name: 'example.com.'
    - is_private: True para privada, False para pública
    - vpc_id, vpc_region: necesarios solo si es privada
    Devuelve:
      - Si pública: (zone_id, [ns1, ns2, ...])
      - Si privada: (zone_id, None)
    """
    kwargs = {
        "Name": zone_name,
        "CallerReference": str(time.time()),
        "HostedZoneConfig": {"Comment": comment}
    }

    if is_private:
        if not vpc_id or not vpc_region:
            raise ValueError("Para zonas privadas debes indicar vpc_id y vpc_region")
        kwargs["VPC"] = {
            "VPCRegion": vpc_region,
            "VPCId": vpc_id
        }
        kwargs["HostedZoneConfig"]["PrivateZone"] = True

    response = route53.create_hosted_zone(**kwargs)
    zone_id = response["HostedZone"]["Id"]
    if not is_private:
        # Busca el record de NS
        for record in response["DelegationSet"]["NameServers"]:
            print("NS:", record)
        ns_list = response["DelegationSet"]["NameServers"]
        return zone_id, ns_list
    else:
        return zone_id, None


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

    role_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-role-oidc"
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

    policy_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-policy-oidc"
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

    s3_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-s3-tf"
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
        print(f"S3 bucket already exists, skipping")
    else:
        create_s3(s3, s3_name, s3_policy, account_region)
        print(f"S3 bucket created")

    # KeyPair

    keypair_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-keypair-main"

    if check_keypair_exists(ec2, keypair_name):
        print("Key pair exists, skipping")
        keypair_id = keypair_name
    else:
        keypair_id = create_keypair(ec2, keypair_name)
        keypair_file = os.path.join(os.path.expanduser("~"), f"{keypair_name}.pem")
        with open(keypair_file, "w") as f:
            f.write(keypair_id)
        print(f"Private key saved to {keypair_file}")

    # VPC

    vpc_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-vpc-main"

    if check_vpc_exists(ec2, vpc_name):
        print("Vpc exists, skipping")
        vpc_id = get_vpc_id(ec2, vpc_name)
    else:
        vpc_id = create_vpc(ec2, vpc_name, vars_json['vpc_cidr'], vars_json['vpc_ipv6'])
        print(f"Vpc created")

    # Subnets

    azs = get_available_azs(ec2)
    azs_len = len(azs)
    public_subnets_cidr = [str(ipaddress.IPv4Network(f"10.0.{i}.0/24")) for i in range(azs_len)]
    private_subnets_cidr = [str(ipaddress.IPv4Network(f"10.0.{i+10}.0/24")) for i in range(azs_len)]
    subnet_public_ids = []
    subnet_private_ids = []

    for az, subnet_cidr in zip(azs, public_subnets_cidr):
        subnet_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-subnet-pub-{az}"
        if check_subnet_exists(ec2, subnet_name):
            print(f"Subnet '{subnet_name}' already exists, skipping")
            subnet_info = get_subnet_by_name(ec2, subnet_name)
            subnet_id = subnet_info["SubnetId"]
        else:
            subnet_id = create_subnet(ec2, subnet_name, vpc_id, subnet_cidr, az)
            print(f"Subnet public created")
        subnet_public_ids.append(subnet_id)

    for az, subnet_cidr in zip(azs, private_subnets_cidr):
        subnet_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-subnet-priv-{az}"
        if check_subnet_exists(ec2, subnet_name):
            print(f"Subnet '{subnet_name}' already exists, skipping")
            subnet_info = get_subnet_by_name(ec2, subnet_name)
            subnet_id = subnet_info["SubnetId"]
        else:
            subnet_id = create_subnet(ec2, subnet_name, vpc_id, subnet_cidr, az)
            print(f"Subnet private created")
        subnet_private_ids.append(subnet_id)

    # Security groups

    sg_test_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-sg-test"
    sg_natgw_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-sg-natgw"

    if check_sg_exists(ec2, vpc_id, sg_test_name):
        sg_test_id = get_sg_id(ec2, vpc_id, sg_test_name)
        print(f"SG test exists, skipping")
    else:
        sg_test_id = create_sg(ec2, vpc_id, sg_test_name, "test")
        create_sg_inbound_rule(ec2, sg_test_id, protocol="-1", cidr="0.0.0.0/0")
        print(f"SG test created and inbound rule added")

    if check_sg_exists(ec2, vpc_id, sg_natgw_name):
        sg_natgw_id = get_sg_id(ec2, vpc_id, sg_natgw_name)
        print(f"SG natgw exists, skipping")
    else:
        sg_natgw_id = create_sg(ec2, vpc_id, sg_natgw_name, "ec2-natgw")
        print(f"SG natgw created and inbound rule added")

    # IGW

    igw_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-igw-main"

    if check_igw_exists(ec2, igw_name):
        print("IGW exists, skipping")
        igw_id = get_igw_id(ec2, igw_name)
    else:
        igw_id = create_igw(ec2, igw_name)
        attach_igw_to_vpc(ec2, igw_id, vpc_id)
        print("IGW created and attached to VPC")

    # NATGW

    natgw_instance_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-ec2-natgw"
    natgw_ebs_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-ebs-natgw"
    natgw_instance_userdata = f"""#!/bin/bash
    sudo yum update -y
    sudo yum install -y yum-utils
    sudo yum-config-manager --add-repo https://pkgs.tailscale.com/stable/amazon-linux/2023/tailscale.repo
    sudo yum install -y iptables-services tailscale
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
    sudo sysctl -p /etc/sysctl.conf
    ETH_IFACE=$(ip route | grep default | awk '{{print $5}}')
    iptables -t nat -A POSTROUTING -o $ETH_IFACE -j MASQUERADE
    service iptables save
    systemctl enable iptables
    systemctl start iptables
    sudo systemctl enable --now tailscaled
    sudo tailscale up --auth-key={vars_json["vpc_subnet_private_tskey"]} --hostname={natgw_instance_name} --advertise-routes={",".join(private_subnets_cidr)}
    """

    if check_instance_exists(ec2, natgw_instance_name):
        print(f"Ec2 natgw exists, skipping")
        natgw_instance_id = get_instance_id_by_name(ec2, natgw_instance_name)
    else:
        natgw_instance_id = create_ec2_instance(
            ec2,
            natgw_instance_name,
            natgw_ebs_name,
            "t4g.nano",
            "ami-0cd0767d8ed6ad0a9",
            keypair_id,
            subnet_public_ids[0],
            sg_natgw_id,
            natgw_instance_userdata
        )
        disable_source_dest_check(ec2, natgw_instance_id)
        eip_natgw_id = create_eip(ec2)
        associate_eip_to_instance(ec2, eip_natgw_id, natgw_instance_id)
        print(f"Ec2 natgw created and EIP associated, disabled check")

    # Route tables

    rt_pub_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-rt-pub"
    rt_priv_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-rt-priv"

    if check_rt_exists(ec2, vpc_id, rt_pub_name):
        print(f"Route Table public exists, skipping")
    else:
        rt_pub_id = create_rt(ec2, vpc_id, rt_pub_name)
        create_route(ec2, rt_pub_id, '0.0.0.0/0', 'GatewayId', igw_id)
        for subnet_id in subnet_public_ids:
            associate_rt_to_subnet(ec2, subnet_id, rt_pub_id)
        print(f"Route Table public created, added IGW and associated to public subnets")

    if check_rt_exists(ec2, vpc_id, rt_priv_name):
        print(f"Route Table private exists, skipping")
    else:
        rt_priv_id = create_rt(ec2, vpc_id, rt_priv_name)
        create_route(ec2, rt_priv_id, '0.0.0.0/0', 'InstanceId', natgw_instance_id)
        for subnet_id in subnet_private_ids:
            associate_rt_to_subnet(ec2, subnet_id, rt_priv_id)
        print(f"Route Table private created and associated to private subnets")

    # Hostedzones

    for zone in vars_json["hostedzones_public"]:
        zone_name = zone if zone.endswith('.') else zone + '.'
        if check_hosted_zone_exists(route53, zone_name):
            print(f"Public Hosted Zone '{zone_name}' exists, skipping")
        else:
            zone_id, ns_list = create_hosted_zone(route53, zone_name, is_private=False)
            print(f"Public Hosted zone created '{zone_name}'. Zone ID: {zone_id}, Nameservers: {ns_list}")

    for zone in vars_json["hostedzones_private"]:
        zone_name = zone if zone.endswith('.') else zone + '.'
        if check_hosted_zone_exists(route53, zone_name):
            print(f"Privatee Hosted Zone '{zone_name}' exists, skipping")
        else:
            zone_id = create_hosted_zone(route53, zone_name, is_private=True, vpc_id=vpc_id, vpc_region=account_region)
            print(f"Private Hosted zone Created '{zone_name}'")

if __name__ == "__main__":
    main()