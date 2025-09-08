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

# Load vars

script_dir = os.path.dirname(os.path.abspath(__file__))
vars_path = os.path.join(script_dir, "vars.json")

with open(vars_path) as f:
    vars = json.load(f)

# Validation

REQUIRED_VARS = [
    "project_name",
    "project_environment",
    "vpc_cidr",
    "vpc_ipv6",
    "hostedzones_public",
    "hostedzones_private",
    "vpc_subnet_private_tskey",
    "github_account",
    "github_repo"
]

ARRAY_VARS = [
    "hostedzones_public",
    "hostedzones_private"
]

missing = [var for var in REQUIRED_VARS if var not in vars]
wrong_type = [var for var in ARRAY_VARS if var in vars and not isinstance(vars[var], list)]

if missing or wrong_type:
    if missing:
        print(f"Missing required variables in vars.json: {', '.join(missing)}", file=sys.stderr)
    if wrong_type:
        print(f"These variables must be arrays (even if empty): {', '.join(wrong_type)}", file=sys.stderr)
    sys.exit(1)

if "/" not in vars["vpc_cidr"]:
    print("vpc_cidr must include a subnet mask (e.g., 10.0.0.0/16)", file=sys.stderr)
    sys.exit(1)

try:
    ipaddress.IPv4Network(vars["vpc_cidr"])
except Exception:
    print("vpc_cidr must be a valid IPv4 CIDR (e.g., 10.0.0.0/16)", file=sys.stderr)
    sys.exit(1)

# Variables

account_id = sts.get_caller_identity()["Account"]
account_region = session.region_name
account_azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]]
ami_al2023 = ec2.describe_images(Owners=['amazon'],Filters=[
        {"Name": "name", "Values": ["al2023-ami-*-arm64"]},
        {"Name": "architecture", "Values": ["arm64"]},
        {"Name": "state", "Values": ["available"]},
        {"Name": "root-device-type", "Values": ["ebs"]},
        {"Name": "virtualization-type", "Values": ["hvm"]},
    ]
)
ami = sorted(ami_al2023['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]
ami_id = ami['ImageId']
project_name = vars["project_name"]
project_env = vars["project_environment"]

### MOVER

hostedzones_public = vars["hostedzones_public"]
hostedzones_private = vars["hostedzones_private"]

public_rt_name = f"{project_name}-{project_env}-rt-public-bootstrap"
private_rt_name = f"{project_name}-{project_env}-rt-private-bootstrap"



# VPC

vpc_name = f"{project_name}-{project_env}-vpc-bootstrap"
vpc_cidr = vars["vpc_cidr"]
vpc_ipv6 = vars["vpc_ipv6"]
vpc_network = ipaddress.ip_network(vpc_cidr)
list_vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [vpc_name]}])
vpc_names = list_vpcs.get("Vpcs", [])

if vpc_names:
    print(f"VPC exists, skipping creation")
    vpc_id = vpc_names[0]["VpcId"]
else:
    create_vpc = ec2.create_vpc(CidrBlock=vpc_cidr)
    vpc_id = create_vpc["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": vpc_name}])
    print(f"VPC created: {vpc_id}")
    if str(vpc_ipv6).lower() == "true":
        ipv6_assoc = ec2.associate_vpc_cidr_block(
            VpcId=vpc_id,
            AmazonProvidedIpv6CidrBlock=True
        )
        ipv6_assoc.get("Ipv6CidrBlockAssociation", {})
        print(f"IPv6 enabled for VPC")
    else:
        print("IPv6 not enabled for VPC.")

# Security Groups

sg_test_name = f"{project_name}-{project_env}-sg-test-bootstrap"
sg_natgw_name = f"{project_name}-{project_env}-sg-natgw-bootstrap"
list_sg_test = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_test_name]}])
sg_test_groups = list_sg_test.get("SecurityGroups", [])
list_sg_nat = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_natgw_name]}])
sg_natgw_groups = list_sg_nat.get("SecurityGroups", [])

if sg_test_groups:
    print(f"Security Group test exists, skipping creation")
    sg_test_id = sg_test_groups[0]["GroupId"]
else:
    sg_test = ec2.create_security_group(
        GroupName=sg_test_name,
        Description="All open (test)",
        VpcId=vpc_id
    )
    sg_test_id = sg_test["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_test_id,
        IpPermissions=[{
            "IpProtocol": "-1",  # ALL protocols
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }]
    )
    print(f"Security Group {sg_test_name} created")

if sg_natgw_groups:
    print(f"Security Group NAT exists, skipping creation")
    sg_natgw_id = sg_natgw_groups[0]["GroupId"]
else:
    sg_natgw = ec2.create_security_group(
        GroupName=sg_natgw_name,
        Description="All inbound blocked (NAT)",
        VpcId=vpc_id
    )
    sg_natgw_id = sg_natgw["GroupId"]
    print(f"Security Group NAT created")

# Subnets

list_subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
public_subnet_block = list(vpc_network.subnets(new_prefix=24))[0] 
private_subnet_block = list(vpc_network.subnets(new_prefix=24))[1] 
public_subnet_cidr = list(public_subnet_block.subnets(new_prefix=26))
private_subnet_cidr = list(private_subnet_block.subnets(new_prefix=26))
existing_subnets = []

for subnet in list_subnets:
    for tag in subnet.get("Tags", []):
        if tag["Key"] == "Name":
            existing_subnets.append(tag["Value"])

for subnet_type, cidr_list, label in [
    ("public", public_subnet_cidr, "public"),
    ("private", private_subnet_cidr, "private"),
]:
    for i, az in enumerate(account_azs):
        subnet_name = f"{project_name}-{project_env}-subnet-{subnet_type}-{az}-bootstrap"
        if subnet_name in existing_subnets:
            print(f"Subnet {label} {subnet_name} exists, skipping creation")
            continue
        create_subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=str(cidr_list[i]),
            AvailabilityZone=az
        )
        subnet_id = create_subnet["Subnet"]["SubnetId"]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": subnet_name}])
        print(f"Created {label} subnet {subnet_name}")
        existing_subnets.append(subnet_name)

# Gateways

igw_id = None
instance_name = f"{project_name}-{project_env}-ec2-natgw-bootstrap"
volume_name = f"{project_name}-{project_env}-ebs-natgw-bootstrap"
vpc_subnet_private_tskey = vars["vpc_subnet_private_tskey"]
list_igws = ec2.describe_internet_gateways(Filters=[
    {"Name": "attachment.vpc-id",
    "Values": [vpc_id]}])["InternetGateways"]
list_natwg = ec2.describe_instances(Filters=[
    {"Name": "tag:Name", "Values": [instance_name]},
    {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}
])["Reservations"]
private_subnet_cidrs = []
for subnet in list_subnets:
    name = None
    for tag in subnet.get("Tags", []):
        if tag["Key"] == "Name":
            name = tag["Value"]
    if name and "-subnet-private-" in name:
        private_subnet_cidrs.append(subnet["CidrBlock"])
advertise_routes = ",".join(private_subnet_cidrs)
userdata_script = f"""#!/bin/bash
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
sudo tailscale up --auth-key={vpc_subnet_private_tskey} --hostname={instance_name} --advertise-routes={advertise_routes}
"""

if list_igws:
    igw_id = list_igws[0]["InternetGatewayId"]
    print(f"Internet Gateway already exists, skipping creation")
else:
    create_igw = ec2.create_internet_gateway()
    igw_id = create_igw["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(VpcId=vpc_id, InternetGatewayId=igw_id)
    igw_name = f"{project_name}-{project_env}-igw-bootstrap"
    ec2.create_tags(Resources=[igw_id], Tags=[{"Key": "Name", "Value": igw_name}])
    print(f"Created and attached Internet Gateway to VPC")

if list_natwg:
    print(f"Instance natgw already exists, skipping creation")
else:
    subnet_id_nat = None
    for subnet in list_subnets:
        for tag in subnet.get("Tags", []):
            if tag["Key"] == "Name" and "-subnet-public-" in tag["Value"]:
                subnet_id_nat = subnet["SubnetId"]
                break
        if subnet_id_nat:
            break

    create_instance_natgw = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t4g.nano",
        KeyName=keypair_name,
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[
            {
                "SubnetId": subnet_id_nat,
                "DeviceIndex": 0,
                "Groups": [sg_natgw_id],
                "AssociatePublicIpAddress": True
            }
        ],
        UserData=userdata_script,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": instance_name}
                ]
            },
            {
                "ResourceType": "volume",
                "Tags": [
                    {"Key": "Name", "Value": volume_name}
                ]
            }
        ]
    )

    natgw_instance_id = create_instance_natgw["Instances"][0]["InstanceId"]
    network_interface_id = create_instance_natgw["Instances"][0]["NetworkInterfaces"][0]["NetworkInterfaceId"]
    waiter_natgw_instance = ec2.get_waiter('instance_running')
    print(f"Waiting for natgw instance is 'running'...")
    waiter_natgw_instance.wait(InstanceIds=[natgw_instance_id])
    allocation = ec2.allocate_address(Domain='vpc')
    ec2.associate_address(AllocationId=allocation['AllocationId'],NetworkInterfaceId=network_interface_id)
    print(f"Created NAT Gateway EC2 instance and Elastic IP assigned to natgw_instance")