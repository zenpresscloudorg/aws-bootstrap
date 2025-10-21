#!/bin/bash

# Read vars,json

project_name=$(jq -r '.project_name' vars.json)
project_environment=$(jq -r '.project_environment' vars.json)
aws_region=${AWS_REGION}

# Formato del nombre del bucket
bucket_name="${project_name}-bootstrap-${project_environment}-ebs-natgw"

# Terraform

sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
sudo yum -y install terraform

# Bucket

echo "Creando bucket S3: $bucket_name en la región $aws_region"
aws s3api create-bucket --bucket "$bucket_name" --region "$aws_region" --create-bucket-configuration LocationConstraint="$aws_region"

# Generate backend

cat > backend.tf <<EOF
terraform {
	backend "s3" {
		bucket = "$bucket_name"
		key    = "terraform.tfstate"
		region = "$aws_region"
	}
}
EOF

# Run terraform

terraform init
terraform apply -var-file="../vars.json"