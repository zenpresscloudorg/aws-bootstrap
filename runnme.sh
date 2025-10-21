#!/bin/bash

# Read vars.json

project_name=$(jq -r '.project_name' "$(dirname "$0")/vars.json")
project_environment=$(jq -r '.project_environment' "$(dirname "$0")/vars.json")
aws_region=${AWS_REGION}

# Formato del nombre del bucket
bucket_name="${project_name}-bootstrap-${project_environment}-ebs-natgw"

# Terraform

sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
sudo yum -y install terraform

# Bucket

if aws s3api head-bucket --bucket "$bucket_name" 2>/dev/null; then
	echo "El bucket $bucket_name ya existe."
else
	aws s3api create-bucket --bucket "$bucket_name" --region "$aws_region" --create-bucket-configuration LocationConstraint="$aws_region"
	aws s3api put-bucket-versioning --bucket "$bucket_name" --versioning-configuration Status=Enabled
	aws s3api put-bucket-encryption --bucket "$bucket_name" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
	cat > bucket-policy.json <<'EOF'
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Principal": "*",
			"Action": [
				"s3:GetObject",
				"s3:PutObject",
				"s3:ListBucket"
			],
			"Resource": [
				"arn:aws:s3:::$bucket_name",
				"arn:aws:s3:::$bucket_name/*"
			]
		}
	]
}
EOF
	aws s3api put-bucket-policy --bucket "$bucket_name" --policy file://bucket-policy.json
fi

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