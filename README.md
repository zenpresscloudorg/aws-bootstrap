# Whats inside

- Creates github oidc role with limited access to project and env named resources
- Creates tfstate s3 bucket with versioning, encryption and access only to role
- Creates ec2 keypair for project
- Add one or more public domains from the project to Route 53 (optional)

# Usage instructions

## 1) Login in AWS CloudShell (login in aws region you want to bootstrap)

## 2) Clone repository

```bash
git clone https://github.com/edup92/terraform-bootstrap.git
cd terraform-bootstrap
```

## 3) Give execution permissions
```bash
chmod +x script.sh
```

## 4) Run script
```bash
./script.sh
```