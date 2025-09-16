import json
import time
import botocore
import ipaddress

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
    
def get_iam_role_arn(iam, role_name):
    try:
        return iam.get_role(RoleName=role_name)["Role"]["Arn"]
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
    time.sleep(10)
    return resp["Role"]["Arn"]

def get_iam_policy_arn(iam, policy_name, scope="Local"):
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

def update_iam_policy(iam, policy_arn, policy_document):
    """
    Updates the IAM policy by creating a new version and setting it as default.
    Deletes the oldest non-default version if the 5-version limit is reached.
    """
    versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    # If there are 5 versions, delete the oldest non-default version
    if len(versions) >= 5:
        non_default_versions = [v for v in versions if not v["IsDefaultVersion"]]
        oldest = sorted(non_default_versions, key=lambda v: v["CreateDate"])[0]
        iam.delete_policy_version(
            PolicyArn=policy_arn,
            VersionId=oldest["VersionId"]
        )
    iam.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(policy_document),
        SetAsDefault=True
    )

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

def get_vpc_id(ec2, vpc_name):
    """
    Returns the VPC ID if a VPC with the given name exists.
    Returns False if it does not exist.
    """
    response = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [vpc_name]}])
    vpcs = response.get("Vpcs", [])
    if vpcs:
        return vpcs[0]["VpcId"]
    return False

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

def get_subnet_cidrs(vpc_cidr, subnet_prefix, num_subnets):
    """
    Divide el rango vpc_cidr en subredes del tamaño subnet_prefix.
    Devuelve una lista con los CIDRs de las primeras num_subnets subredes.
    """
    vpc_net = ipaddress.IPv4Network(vpc_cidr)
    subnets = list(vpc_net.subnets(new_prefix=subnet_prefix))
    if len(subnets) < num_subnets:
        raise ValueError("No hay suficientes subredes disponibles para el tamaño solicitado")
    return [str(s) for s in subnets[:num_subnets]]

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
        ns_list = response["DelegationSet"]["NameServers"]
        return zone_id, ns_list
    else:
        return zone_id, None
