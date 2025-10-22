
#!/bin/bash

# Vars json
VARS_JSON_PATH="$(dirname "$0")/vars.json"
if [ ! -f "$VARS_JSON_PATH" ]; then
	echo "ERROR: vars.json file does not exist. Cancelling run."
	exit 1
fi

project_name=$(jq -r '.project_name' "$VARS_JSON_PATH")
project_environment=$(jq -r '.project_environment' "$VARS_JSON_PATH")
aws_region=${AWS_REGION}

# Formato del nombre del bucket
bucket_name="${project_name}-bootstrap-${project_environment}-s3-tfstate"

# Terraform

sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
sudo yum -y install terraform

# Bucket

if aws s3api head-bucket --bucket "$bucket_name" 2>/dev/null; then
	echo "Bucket namet $bucket_name already exists."
else
	aws s3api create-bucket --bucket "$bucket_name" --region "$aws_region" --create-bucket-configuration LocationConstraint="$aws_region"
	aws s3api put-bucket-versioning --bucket "$bucket_name" --versioning-configuration Status=Enabled
	aws s3api put-bucket-encryption --bucket "$bucket_name" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
fi

# Generate backend

cat > "$(dirname "$0")/backend.tf" <<EOF
terraform {
	backend "s3" {
		bucket = "$bucket_name"
		key    = "terraform.tfstate"
		region = "$aws_region"
	}
}
EOF

# Run terraform

terraform -chdir="$(dirname "$0")" init
terraform -chdir="$(dirname "$0")" apply -var-file="vars.json"