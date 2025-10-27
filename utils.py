import boto3
import json
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os
import random
import string
import os

def load_vars_json(
    path: str
) -> dict:
    """
    Carga el contenido de vars.json como diccionario y valida las claves requeridas.

    Parámetros:
        path (str): Ruta al archivo vars.json.

    Retorna:
        dict: Diccionario con los datos cargados.
    """
    import os
    required_keys = [
        "account_name",
        "account_environment",
        "account_region",
        "vpc_cidr",
        "vpc_ipv6_enable",
        "tailscale_auth_key",
        "hostedzone_public",
        "gh_org",
        "gh_dispatcher_token",
        "gh_runner_token"
    ]
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File '{path}' does not exist.")
    with open(path, "r") as f:
        data = json.load(f)
    missing = [k for k in required_keys if k not in data]
    if missing:
        raise KeyError(f"Missing required keys in vars.json: {missing}")
    return data


def validate_account_info(
    account_info: dict
):
    """
    Valida que el diccionario account_info contenga las claves requeridas.

    Parámetros:
        account_info (dict): Diccionario con información de la cuenta.
    """
    required_keys = ["account", "environment", "region"]
    missing = [k for k in required_keys if k not in account_info]
    if missing:
        raise KeyError(f"Faltan claves requeridas en account_info: {missing}")

def get_availability_zones(
    region: str
) -> list:
    """
    Devuelve una lista de zonas de disponibilidad para la región AWS indicada.

    Parámetros:
        region (str): Región de AWS.

    Retorna:
        list: Lista de nombres de zonas disponibles.
    """
    ec2 = boto3.client("ec2", region_name=region)
    try:
        response = ec2.describe_availability_zones(
            Filters=[{"Name": "region-name", "Values": [region]}]
        )
        return [az["ZoneName"] for az in response["AvailabilityZones"] if az["State"] == "available"]
    except ClientError as e:
        raise Exception(f"Error getting availability zones: {e}")

def render_user_data(
    template_path,
    context
):
    """
    Renderiza un archivo de user-data usando un template y un diccionario de variables.
    Utiliza string.Template para el reemplazo de variables.
    
    Parámetros:
        template_path (str): Ruta al archivo de template.
        context (dict): Diccionario de variables para el template.
    
    Retorna:
        str: El contenido renderizado como string.
    """
    from string import Template
    with open(template_path, "r") as f:
        template_content = f.read()
    template = Template(template_content)
    rendered = template.safe_substitute(context)
    return rendered

def ensure_aws_key_pair(
    account_info: dict,
    product: str,
    usage: str
) -> str | None:
    """
    Busca el primer key pair de AWS EC2 que coincida con los tags indicados.

    Parámetros:
        account_info (dict): Información de la cuenta.
        product (str): Producto.
        usage (str): Uso.

    Retorna:
        str | None: Nombre del key pair si existe, None si no existe.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    filters = [
        {"Name": "tag:account", "Values": [account_info["account"]]},
        {"Name": "tag:environment", "Values": [account_info["environment"]]},
        {"Name": "tag:region", "Values": [account_info["region"]]},
        {"Name": "tag:product", "Values": [product]},
        {"Name": "tag:usage", "Values": [usage]}
    ]
    try:
        response = ec2.describe_key_pairs(Filters=filters)
        keypairs = response.get("KeyPairs", [])
        if keypairs:
            return keypairs[0].get("KeyName")
        return None
    except ClientError as e:
        raise Exception(f"Error searching key pairs by tags: {e}")


def generate_key_pair() -> tuple[str, str]:
    """
    Genera un par de claves RSA en formato SSH.

    Retorna:
        tuple[str, str]: JSON con las claves privada y pública.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_openssh = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_openssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode('utf-8')
    return json.dumps({
        "private_key": private_openssh,
        "public_key": public_openssh
    }, indent=2)


def create_aws_key_pair(
    account_info: dict,
    product: str,
    usage: str,
    key_material: str = None
) -> str:
    """
    Crea un nuevo key pair de AWS EC2 con nombre aleatorio y tags requeridos.

    Parámetros:
        account_info (dict): Información de la cuenta.
        product (str): Producto.
        usage (str): Uso.
        key_material (str, opcional): Material de la clave.

    Retorna:
        str: Nombre del key pair creado.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    tags = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage}
    ]
    try:
        ec2.create_key_pair(
            KeyName=name,
            TagSpecifications=[{
                "ResourceType": "key-pair",
                "Tags": tags
            }]
        )
        return name
    except ClientError as e:
        raise Exception(f"Error creating key pair: {e}")


def ensure_aws_secret(
    account_info: dict,
    product: str,
    usage: str
) -> dict | None:
    """
    Finds the first AWS Secrets Manager secret matching the given tags.
    Returns a dict with name and arn if found, else None.
    """
    validate_account_info(account_info)
    client = boto3.client("secretsmanager", region_name=account_info["region"])
    filters = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage}
    ]
    try:
        paginator = client.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                secret_tags = {tag["Key"]: tag["Value"] for tag in secret.get("Tags", [])}
                if all(tag["Value"] == secret_tags.get(tag["Key"]) for tag in filters):
                    return {
                        "name": secret.get("Name"),
                        "arn": secret.get("ARN")
                    }
        return None
    except ClientError as e:
        raise Exception(f"Error loading secret: {e}")


def create_aws_secret(
    account_info: dict,
    product: str,
    usage: str,
    secret_value: str
) -> dict:
    """
    Creates a new AWS Secrets Manager secret with tags and value.
    The secret name is a random 12-character alphanumeric string.
    Returns a dict with name and arn.
    """
    validate_account_info(account_info)
    client = boto3.client("secretsmanager", region_name=account_info["region"])
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    tags = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage}
    ]
    try:
        response = client.create_secret(
            Name=name,
            SecretString=secret_value,
            Tags=tags
        )
        return {
            "name": name,
            "arn": response["ARN"]
        }
    except ClientError as e:
        raise Exception(f"Error creating secret: {e}")


def ensure_aws_vpc(
    account_info: dict,
    product: str,
    usage: str
) -> str | None:
    """
    Finds the first VPC in AWS matching the given tags.
    Returns the vpc_id if found, else None.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    filters = [
        {"Name": "tag:account", "Values": [account_info["account"]]},
        {"Name": "tag:environment", "Values": [account_info["environment"]]},
        {"Name": "tag:region", "Values": [account_info["region"]]},
        {"Name": "tag:product", "Values": [product]},
        {"Name": "tag:usage", "Values": [usage]}
    ]
    try:
        response = ec2.describe_vpcs(Filters=filters)
        vpcs = response.get("Vpcs", [])
        if vpcs:
            vpc = vpcs[0]
            return vpc["VpcId"]
        return None
    except ClientError as e:
        raise Exception(f"Error loading VPC: {e}")


def create_aws_vpc(
    account_info: dict,
    product: str,
    usage: str,
    cidr_block: str,
    ipv6_enable: bool = False
) -> str:
    """
    Creates a new VPC in AWS with a random name, required tags, and optionally IPv6.
    Returns the created vpc_id.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    tags = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage},
        {"Key": "Name", "Value": name}
    ]
    try:
        response = ec2.create_vpc(CidrBlock=cidr_block)
        vpc_id = response["Vpc"]["VpcId"]
        ec2.create_tags(Resources=[vpc_id], Tags=tags)
        if ipv6_enable:
            ec2.assign_ipv6_cidr_block(VpcId=vpc_id, AmazonProvidedIpv6CidrBlock=True)
        return vpc_id
    except ClientError as e:
        raise Exception(f"Error creating VPC: {e}")


def ensure_aws_subnet(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str
) -> str | None:
    """
    Finds the first Subnet in AWS matching the given tags and vpc_id.
    Returns a dict with id and cidr if found, else None.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    filters = [
        {"Name": "tag:account", "Values": [account_info["account"]]},
        {"Name": "tag:environment", "Values": [account_info["environment"]]},
        {"Name": "tag:region", "Values": [account_info["region"]]},
        {"Name": "tag:product", "Values": [product]},
        {"Name": "tag:usage", "Values": [usage]},
        {"Name": "vpc-id", "Values": [vpc_id]}
    ]
    try:
        response = ec2.describe_subnets(Filters=filters)
        subnets = response.get("Subnets", [])
        if subnets:
            subnet = subnets[0]
            return {"id": subnet["SubnetId"], "cidr": subnet["CidrBlock"]}
        return None
    except ClientError as e:
        raise Exception(f"Error loading Subnet: {e}")


def create_aws_subnet(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str,
    cidr_block: str,
    availability_zone: str,
    map_public_ip_on_launch: bool
) -> str:
    """
    Creates a new Subnet in AWS with a random name and required tags.
    Returns a dict with id and cidr of the created subnet.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    tags = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage},
        {"Key": "Name", "Value": name}
    ]
    params = {
        "VpcId": vpc_id,
        "CidrBlock": cidr_block,
        "MapPublicIpOnLaunch": map_public_ip_on_launch,
        "AvailabilityZone": availability_zone
    }
    try:
        response = ec2.create_subnet(**params)
        subnet = response["Subnet"]
        subnet_id = subnet["SubnetId"]
        cidr = subnet["CidrBlock"]
        ec2.create_tags(Resources=[subnet_id], Tags=tags)
        return {"id": subnet_id, "cidr": cidr}
    except ClientError as e:
        raise Exception(f"Error creating Subnet: {e}")


def ensure_aws_security_group(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str
) -> str | None:
    """
    Finds the first Security Group in AWS matching the given tags and vpc_id.
    Returns the security group id if found, else None.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    filters = [
        {"Name": "tag:account", "Values": [account_info["account"]]},
        {"Name": "tag:environment", "Values": [account_info["environment"]]},
        {"Name": "tag:region", "Values": [account_info["region"]]},
        {"Name": "tag:product", "Values": [product]},
        {"Name": "tag:usage", "Values": [usage]},
        {"Name": "vpc-id", "Values": [vpc_id]}
    ]
    try:
        response = ec2.describe_security_groups(Filters=filters)
        sgs = response.get("SecurityGroups", [])
        if sgs:
            sg = sgs[0]
            return sg["GroupId"]
        return None
    except ClientError as e:
        raise Exception(f"Error loading Security Group: {e}")


def create_aws_security_group(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str,
    description: str = "Managed by bootstrap script",
    inbound_rules: list = None,
    outbound_rules: list = None
) -> str:
    """
    Creates a new Security Group in AWS with a random name, required tags, and optional rules.
    Returns the security group id created.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    tags = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage},
        {"Key": "Name", "Value": name}
    ]
    try:
        response = ec2.create_security_group(
            GroupName=name,
            Description=description,
            VpcId=vpc_id,
            TagSpecifications=[{
                "ResourceType": "security-group",
                "Tags": tags
            }]
        )
        sg_id = response["GroupId"]
        # Inbound rules
        if inbound_rules:
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=inbound_rules
            )
        # Outbound rules
        if outbound_rules:
            ec2.authorize_security_group_egress(
                GroupId=sg_id,
                IpPermissions=outbound_rules
            )
        else:
            # Default allow all outbound
            ec2.authorize_security_group_egress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            )
        return sg_id
    except ClientError as e:
        raise Exception(f"Error creating Security Group: {e}")


def ensure_aws_instance(account_info, product, usage):
    """
    Busca una instancia EC2 por tags (Product, Usage).
    Devuelve un dict con InstanceId y estado si existe, o None si no existe.
    """
    validate_account_info(account_info)
    ec2 = boto3.client('ec2', region_name=account_info["region"])
    filters = [
        {"Name": "tag:product", "Values": [product]},
        {"Name": "tag:usage", "Values": [usage]}
    ]
    resp = ec2.describe_instances(Filters=filters)
    for reservation in resp.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            if instance["State"]["Name"] != "terminated":
                return {
                    "id": instance["InstanceId"],
                    "state": instance["State"]["Name"]
                }
    return None

def create_aws_instance(account_info, product, usage, ami, instance_type, disk_type, disk_size, sg_id, subnet_id, key_name, delete_on_termination=True, userdata=None):
    """
    Crea una instancia EC2 con los parámetros indicados.
    instance_type: tipo de instancia (ej: t3.micro)
    delete_on_termination: bool para el disco raíz
    userdata: opcional
    Devuelve un dict con InstanceId y estado.
    """
    validate_account_info(account_info)
    ec2 = boto3.client('ec2', region_name=account_info["region"])
    name_id = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    block_device = [{
        "DeviceName": "/dev/xvda",
        "Ebs": {
            "VolumeSize": disk_size,
            "VolumeType": disk_type,
            "DeleteOnTermination": delete_on_termination,
            "TagSpecifications": [{
                "ResourceType": "volume",
                "Tags": [
                    {"Key": "Name", "Value": name_id}
                ]
            }]
        }
    }]
    params = {
        "ImageId": ami,
        "InstanceType": instance_type,
        "KeyName": key_name,
        "SecurityGroupIds": [sg_id],
        "SubnetId": subnet_id,
        "BlockDeviceMappings": block_device,
        "TagSpecifications": [{
            "ResourceType": "instance",
            "Tags": [
                {"Key": "product", "Value": product},
                {"Key": "usage", "Value": usage},
                {"Key": "Name", "Value": name_id}
            ]
        }]
    }
    if userdata:
        params["UserData"] = userdata
    resp = ec2.run_instances(
        MinCount=1,
        MaxCount=1,
        **params
    )
    instance = resp["Instances"][0]
    return {
        "id": instance["InstanceId"],
        "state": instance["State"]["Name"]
    }

def set_instance_source_dest_check(account_info, instance_id, value: bool):
    """
    Aplica el parámetro SourceDestCheck a una instancia EC2.
    value: True o False
    """
    ec2 = boto3.client('ec2', region_name=account_info["region"])
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        SourceDestCheck={"Value": value}
    )

def ensure_aws_internet_gateway(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str
) -> str | None:
    """
    Finds the first Internet Gateway (IGW) in AWS matching the given tags and vpc_id.

    Parameters:
        account_info (dict): Account information.
        product (str): Product.
        usage (str): Usage.
        vpc_id (str): VPC ID.

    Returns:
        str | None: IGW ID if exists, None otherwise.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    filters = [
        {"Name": "tag:account", "Values": [account_info["account"]]},
        {"Name": "tag:environment", "Values": [account_info["environment"]]},
        {"Name": "tag:region", "Values": [account_info["region"]]},
        {"Name": "tag:product", "Values": [product]},
        {"Name": "tag:usage", "Values": [usage]},
        {"Name": "attachment.vpc-id", "Values": [vpc_id]}
    ]
    try:
        response = ec2.describe_internet_gateways(Filters=filters)
        igws = response.get("InternetGateways", [])
        if igws:
            return igws[0]["InternetGatewayId"]
        return None
    except ClientError as e:
        raise Exception(f"Error buscando IGW por tags: {e}")

def create_aws_internet_gateway(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str
) -> str:
    """
    Creates an Internet Gateway (IGW) in AWS and attaches it to the specified VPC, with required tags.

    Parameters:
        account_info (dict): Account information.
        product (str): Product.
        usage (str): Usage.
        vpc_id (str): VPC ID.

    Returns:
        str: Created IGW ID.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    tags = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage},
        {"Key": "Name", "Value": name}
    ]
    try:
        response = ec2.create_internet_gateway(
            TagSpecifications=[{
                "ResourceType": "internet-gateway",
                "Tags": tags
            }]
        )
        igw_id = response["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(
            InternetGatewayId=igw_id,
            VpcId=vpc_id
        )
        return igw_id
    except ClientError as e:
        raise Exception(f"Error creando IGW: {e}")

def ensure_aws_route_table(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str
) -> str | None:
    """
    Checks if a Route Table exists in AWS matching the given tags and vpc_id.
    Returns the route_table_id if it exists, None otherwise.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    filters = [
        {"Name": "tag:account", "Values": [account_info["account"]]},
        {"Name": "tag:environment", "Values": [account_info["environment"]]},
        {"Name": "tag:region", "Values": [account_info["region"]]},
        {"Name": "tag:product", "Values": [product]},
        {"Name": "tag:usage", "Values": [usage]},
        {"Name": "vpc-id", "Values": [vpc_id]}
    ]
    try:
        response = ec2.describe_route_tables(Filters=filters)
        rts = response.get("RouteTables", [])
        if rts:
            return rts[0]["RouteTableId"]
        return None
    except ClientError as e:
        raise Exception(f"Error checking Route Table: {e}")

def create_aws_route_table(
    account_info: dict,
    product: str,
    usage: str,
    vpc_id: str
) -> str:
    """
    Creates a Route Table in AWS with the required tags.
    Returns the created route_table_id.
    """
    validate_account_info(account_info)
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    tags = [
        {"Key": "account", "Value": account_info["account"]},
        {"Key": "environment", "Value": account_info["environment"]},
        {"Key": "region", "Value": account_info["region"]},
        {"Key": "product", "Value": product},
        {"Key": "usage", "Value": usage},
        {"Key": "Name", "Value": name}
    ]
    try:
        response = ec2.create_route_table(VpcId=vpc_id)
        rt_id = response["RouteTable"]["RouteTableId"]
        ec2.create_tags(Resources=[rt_id], Tags=tags)
        return rt_id
    except ClientError as e:
        raise Exception(f"Error creating Route Table: {e}")

def ensure_aws_route(
    account_info: dict,
    route_table_id: str,
    destination_cidr_block: str
) -> bool:
    """
    Checks if a Route exists in the given Route Table with the specified destination.
    Returns True if it exists, False otherwise.
    """
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    try:
        response = ec2.describe_route_tables(RouteTableIds=[route_table_id])
        rts = response.get("RouteTables", [])
        if not rts:
            return False
        for route in rts[0].get("Routes", []):
            if route.get("DestinationCidrBlock") == destination_cidr_block:
                return True
        return False
    except ClientError as e:
        raise Exception(f"Error checking Route: {e}")

def create_aws_route(
    account_info: dict,
    route_table_id: str,
    destination_cidr_block: str,
    gateway_id: str = None,
    instance_id: str = None,
    nat_gateway_id: str = None
) -> bool:
    """
    Creates a Route in the specified Route Table. You can specify gateway, instance, or NAT GW.
    Returns True if creation was successful.
    """
    ec2 = boto3.client("ec2", region_name=account_info["region"])
    params = {
        "RouteTableId": route_table_id,
        "DestinationCidrBlock": destination_cidr_block
    }
    if gateway_id:
        params["GatewayId"] = gateway_id
    if instance_id:
        params["InstanceId"] = instance_id
    if nat_gateway_id:
        params["NatGatewayId"] = nat_gateway_id
    try:
        ec2.create_route(**params)
        return True
    except ClientError as e:
        raise Exception(f"Error creating Route: {e}")