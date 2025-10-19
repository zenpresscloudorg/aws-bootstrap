# Imports

import os
import boto3
from validators import load_and_validate_vars_json
from aws_utils import *

# Clients

iam = boto3.client("iam")
sts = boto3.client("sts")
s3 = boto3.client("s3")
ec2 = boto3.client("ec2")
route53 = boto3.client("route53")
session = boto3.session.Session()

# Main

def main():

  # Vars

  vars_json = load_and_validate_vars_json("vars.json")
  account_id = sts.get_caller_identity()["Account"]
  account_region = session.region_name

  # Common vars

  name_structure = f"{vars_json['project_name']}-{vars_json['project_environment']}-bootstrap-RESOURCE-oidc"

  # Common vars
  
  name_structure = "{project}-{env}-{resource}"

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

  role_name = f"{vars_json['project_name']}-{vars_json['project_environment']}-bootstrap-role-oidc"
  role_arn = get_iam_role_arn(iam, role_name)
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

  if role_arn:
      print("IAM role already exists, skipping")
  else:
      role_arn = create_iam_role(iam, role_name, trust_policy)
      print(f"IAM role created, Name {role_name}")

  # Role policy

  policy_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-policy-oidc"
  policy_arn = get_iam_policy_arn(iam, policy_name)
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

  if policy_arn:
      print("IAM Policy already exists, updating...")
      update_iam_policy(iam, policy_arn, policy_document)
  else:
      policy_arn = create_iam_policy(iam, policy_name, policy_document)
      attach_policy_to_role(iam, role_name, policy_arn)
      print("IAM Policy created and attached to Role")

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
      print(f"S3 bucket created, Name {s3_name}")

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
      print(f"Private key saved to {keypair_file}, Please download the file")

  # VPC

  vpc_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-vpc-main"
  vpc_id = get_vpc_id(ec2, vpc_name)

  if vpc_id:
      print("Vpc exists, skipping")
  else:
      vpc_id = create_vpc(ec2, vpc_name, vars_json['vpc_cidr'], vars_json['vpc_ipv6_enable'])
      print(f"Vpc created, Name {vpc_name}")


  # Subnets

  azs = get_available_azs(ec2)
  azs_len = len(azs)
  public_subnets_cidr = get_subnet_cidrs(vars_json['vpc_cidr'], 24, azs_len)
  private_subnets_cidr = get_subnet_cidrs(vars_json['vpc_cidr'], 24, azs_len * 2)[azs_len:azs_len*2]
  subnet_public_ids = []
  subnet_private_ids = []

  for az, subnet_cidr in zip(azs, public_subnets_cidr):
      subnet_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-subnet-pub-{az}"
      subnet_info = get_subnet_by_name(ec2, subnet_name)
      if subnet_info:
          print(f"Subnet '{subnet_name}' already exists, skipping")
          subnet_id = subnet_info["SubnetId"]
      else:
          subnet_id = create_subnet(ec2, subnet_name, vpc_id, subnet_cidr, az)
          print(f"Subnet public created, Name {subnet_name}")
      subnet_public_ids.append(subnet_id)

  if vars_json.get('vpc_subnet_private_enable', False):
      for az, subnet_cidr in zip(azs, private_subnets_cidr):
          subnet_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-subnet-priv-{az}"
          subnet_info = get_subnet_by_name(ec2, subnet_name)
          if subnet_info:
              print(f"Subnet '{subnet_name}' already exists, skipping")
              subnet_id = subnet_info["SubnetId"]
          else:
              subnet_id = create_subnet(ec2, subnet_name, vpc_id, subnet_cidr, az)
              print(f"Subnet public created, Name {subnet_name}")

          subnet_private_ids.append(subnet_id)

  # Security groups

  sg_test_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-sg-test"
  sg_natgw_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-sg-natgw"
  sg_ghrunner_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-sg-natgw"
  sg_test_id = get_sg_id(ec2, vpc_id, sg_test_name)
  sg_natgw_id = get_sg_id(ec2, vpc_id, sg_natgw_name)
  sg_ghrunner_id = get_sg_id(ec2, vpc_id, sg_ghrunner_name)

  if sg_test_id:
      print(f"SG test exists, skipping")
  else:
      sg_test_id = create_sg(ec2, vpc_id, sg_test_name, "test")
      create_sg_inbound_rule(ec2, sg_test_id, protocol="-1", cidr="0.0.0.0/0")
      print(f"SG test created and inbound rule added, Name {sg_test_name}")

  if sg_natgw_id:
      print(f"SG natgw exists, skipping")
  else:
      sg_natgw_id = create_sg(ec2, vpc_id, sg_natgw_name, "ec2-natgw")
      print(f"SG natgw created, Name {sg_test_name}")

  if sg_ghrunner_id:
      print(f"SG natgw exists, skipping")
  else:
      sg_ghrunner_id = create_sg(ec2, vpc_id, sg_ghrunner_name, "ec2-natgw")
      print(f"SG natgw created, Name {sg_test_name}")

  # IGW

  igw_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-igw-main"
  igw_id = get_igw_id(ec2, igw_name)

  if igw_id:
      print("IGW exists, skipping")
  else:
      igw_id = create_igw(ec2, igw_name)
      attach_igw_to_vpc(ec2, igw_id, vpc_id)
      print(f"IGW created and attached to VPC, Name {igw_name}")

  # NATGW

  if vars_json.get('vpc_subnet_private_enable', False):
      natgw_instance_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-ec2-natgw"
      natgw_ebs_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-ebs-natgw"
      natgw_instance_id = get_instance_id_by_name(ec2, natgw_instance_name)
      dnsmasq_servers = ''.join([f'server=/{domain}/$ROUTE53_RESOLVER\\n' for domain in vars_json["hostedzones_private"]])
      natgw_instance_userdata = f"""#!/bin/bash
      sudo yum update -y
      sudo yum install -y yum-utils ipcalc
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
      NET_DEV=$(ip route | awk '/default/ {{print $5; exit}}')
      CIDR=$(ip -o -f inet addr show $NET_DEV | awk '{{print $4}}')
      NETWORK=$(ipcalc -n $CIDR | awk -F= '/NETWORK/ {{print $2}}')
      IFS=. read n1 n2 n3 n4 <<< "$NETWORK"
      ROUTE53_RESOLVER="$n1.$n2.$n3.$((n4 + 2))"
      sudo yum install -y dnsmasq
      cat <<EOF | sudo tee /etc/dnsmasq.conf
      interface=tailscale0
      bind-dynamic
      no-resolv
      {dnsmasq_servers}
      port=53
      EOF
      sudo systemctl enable dnsmasq
      sudo systemctl restart dnsmasq
      """

      if natgw_instance_id:
          print(f"Ec2 natgw exists, skipping")
      else:
          natgw_instance_id = create_ec2_instance(
              ec2,
              natgw_instance_name,
              natgw_ebs_name,
              "t4g.nano",
              "ami-0cd0767d8ed6ad0a9",
              keypair_id,
              subnet_public_ids[0],
              [sg_natgw_id],
              natgw_instance_userdata
          )
          disable_source_dest_check(ec2, natgw_instance_id)
          eip_natgw_id = create_eip(ec2)
          associate_eip_to_instance(ec2, eip_natgw_id, natgw_instance_id)
          print(f"Ec2 natgw created and EIP associated, disabled check, Name {natgw_instance_name}")

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
      print(f"Route Table public created, added IGW and associated to public subnets, Name {rt_pub_name}")

  if vars_json.get('vpc_subnet_private_enable', False):
      if check_rt_exists(ec2, vpc_id, rt_priv_name):
          print(f"Route Table private exists, skipping")
      else:
          rt_priv_id = create_rt(ec2, vpc_id, rt_priv_name)
          create_route(ec2, rt_priv_id, '0.0.0.0/0', 'InstanceId', natgw_instance_id)
          for subnet_id in subnet_private_ids:
              associate_rt_to_subnet(ec2, subnet_id, rt_priv_id)
          print(f"Route Table private created and associated to private subnets, Name {rt_priv_name}")

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

  # Github runner
  ghrunner_instance_name = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-ec2-ghrunner"
  ghrunner_ebs_name      = f"{vars_json['project_name']}-bootstrap-{vars_json['project_environment']}-ebs-ghrunner"
  ghrunner_instance_id   = get_instance_id_by_name(ec2, ghrunner_instance_name)
  ghrunner_instance_userdata = f"""#!/bin/bash

  ### 1. Variables de configuración

  ### ─── 1. CONFIGURE THESE VARIABLES ─────────────────────────
  GH_OWNER="your-org"          # Change to your organisation/user
  GH_REPO="your-repo"          # Repository name
  RUNNER_TOKEN="YOUR_TOKEN"    # Registration token (24 h validity)
  RUNNER_NAME="$(hostname)"
  RUNNER_LABELS="al2023,arm64"

  ### ─── 2. UPDATE OS & INSTALL DEPENDENCIES ──────────────────
  sudo yum update -y
  sudo yum install -y curl tar gzip jq

  ### ─── 3. CREATE DEDICATED SERVICE USER ─────────────────────
  sudo useradd --system --create-home --shell /bin/bash runner

  ### ─── 4. DOWNLOAD LATEST RUNNER BINARY (arm64) ─────────────
  ARCH=arm64
  RUNNER_VERSION="$(curl -s https://api.github.com/repos/actions/runner/releases/latest | jq -r .tag_name | tr -d 'v')"
  RUNNER_HOME="/opt/actions-runner"

  sudo mkdir -p ${{RUNNER_HOME}}
  cd ${{RUNNER_HOME}}
  sudo curl -Ls -o "actions-runner-linux-${{ARCH}}-${{RUNNER_VERSION}}.tar.gz" \
      "https://github.com/actions/runner/releases/download/v${{RUNNER_VERSION}}/actions-runner-linux-${{ARCH}}-${{RUNNER_VERSION}}.tar.gz"
  sudo tar -xzf "actions-runner-linux-${{ARCH}}-${{RUNNER_VERSION}}.tar.gz"
  sudo chown -R runner:runner ${{RUNNER_HOME}}

  ### ─── 5. INSTALL LIB DEPENDENCIES & CONFIGURE ──────────────
  sudo -u runner ./bin/installdependencies.sh

  sudo -u runner ./config.sh \
    --url "https://github.com/${{GH_OWNER}}/${{GH_REPO}}" \
    --token "${{RUNNER_TOKEN}}" \
    --name "${{RUNNER_NAME}}" \
    --labels "${{RUNNER_LABELS}}" \
    --unattended --replace

  ### ─── 6. INSTALL & START SYSTEMD SERVICE ───────────────────
  cd ${{RUNNER_HOME}}
  sudo ./svc.sh install runner
  sudo systemctl enable --now "actions.runner.${{GH_OWNER}}-${{GH_REPO}}.${{RUNNER_NAME}}.service"
  """

  vars_json['project_environment']

  if ghrunner_instance_id:
      print("EC2 ghrunner exists, skipping")
  else:
      ghrunner_instance_id = create_ec2_instance(
          ec2,
          ghrunner_instance_name,
          ghrunner_ebs_name,
          "t4g.nano",
          "ami-0cd0767d8ed6ad0a9",
          keypair_id,
          subnet_public_ids[0],
          [sg_ghrunner_id],
          ghrunner_instance_userdata
      )
      print(f"EC2 ghrunner created, Name {ghrunner_instance_name}")


  # SES

if __name__ == "__main__":
  main()