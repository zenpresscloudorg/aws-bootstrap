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

### 2) Create github token to add runner

1. Create Fine-Grained token [GitHub](https://github.com/settings/personal-access-tokens).
2. Under **Resource owner**, select your **organization**.
3. Under **Repository access**, choose **All repositories**.
4. Under **Permissions**, set:
   - **Administration** → *Read and write*  
   - **Actions** → *Read and write*
5. Set an **expiration date of 7 days** (required).  
6. Click **Generate token**.

### 3) Clone repository

```bash
git clone https://github.com/zenpresscloudorg/aws-bootstrap
```

### 4) Create vars.json file
```bash
cat > aws-bootstrap/vars.json <<EOF
{
   "project_name":"demo",
   "project_environment":"dev/prod",
   "vpc_cidr": "10.0.0.0/16 (must be cidr format)", 
   "vpc_ipv6_enable": true/false,
   "vpc_subnet_private_tskey": "Token from tailscale auth section",
   "hostedzones_public": "demo.demo",
   "hostedzones_private": "demo.demo",
   "github_org": "github organization name",
   "github_pat": "The token generated in github"
}
EOF
```

### 5) Run runme.sh

```bash
chmod +x aws-bootstrap/runnme.sh ; aws-bootstrap/runnme.sh
```