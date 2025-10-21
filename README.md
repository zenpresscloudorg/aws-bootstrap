# AWS account bootstrap out of the box terraform

# Whats inside

- Creates github oidc role with limited access to project and env named resources
- Creates tfstate s3 bucket with versioning, encryption and access only to role
- Creates ec2 keypair for project
- Add one or more public domains from the project to Route 53 (optional)
- Creates AZ VPC with 1 public subnet, 1 private subnet with NAT router+tailscale (Optional)
    - Instance details: ARM Amazon linux 2023, arm on public Subnet, with inbound denied security group and created keypair
    - Tailscale details: Adds machine to Taiscale, added subnet to access nat private instances you need to approbe subnets
    - Nat details: NAT forwarded to allow outbound internet traffic from nat subnet
- Creates one all open security group (testing purposes)
- Creates Github runner

# Usage instructions

### 1) Login in AWS CloudShell (login in aws region you want to bootstrap)

### 2) Clone repository

```bash
git clone https://github.com/zenpresscloudorg/aws-bootstrap
```

### 4) Modify vars.json file. 
    Notes:
    - VPC CIDR must be /16
    - vpc_ipv6_enable must be true or false
    - "hostedzones_public" and "hostedzones_private" arrays can be empty
    - vpc_subnet_private_enable must be true or false. If is true You need a tailscale api key to access private subnet resources
    - github_org
    - github_runner_token

### 5) Run runme.sh

```bash
chmod +x ./aws-bootstrap/runme.sh ; ./aws-bootstrap/runme.sh
```