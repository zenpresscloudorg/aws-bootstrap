
# Variables

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


### MOVER

hostedzones_public = vars["hostedzones_public"]
hostedzones_private = vars["hostedzones_private"]

public_rt_name = f"{project_name}-{project_env}-rt-public-bootstrap"
private_rt_name = f"{project_name}-{project_env}-rt-private-bootstrap"




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