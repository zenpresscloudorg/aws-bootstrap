# AWS account bootstrap out of the box terraform

# Whats inside

- Creates github oidc role with limited access to project and env named resources
- Creates tfstate s3 bucket with versioning, encryption and access only to role
- Creates ec2 keypair for project
- Add one or more public domains from the project to Route 53 (optional)
- Creates AZ VPC with 1 public subnet, 1 private subnet and 1 private subnet with NAT router+tailscale
    - Instance details: ARM Amazon linux 2023, arm on public Subnet, with inbound denied security group and created keypair
    - Tailscale details: Adds machine to Taiscale, added subnet to access nat private instances you need to approbe subnets
    - Nat details: NAT forwarded to allow outbound internet traffic from nat subnet
- Creates one all open security group (testing purposes)

# Usage instructions

### 1) Login in AWS CloudShell (login in aws region you want to bootstrap)

### 2) Clone repository

```bash
git clone https://github.com/edup92/aws-bootstrap.git
```

### 3) Modify vars.json file

### 4) Run

```bash
python3 ./aws-bootstrap/main.py
```