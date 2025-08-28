#!/bin/bash

# Questions

read -p "Enter project name: " projectname
read -p "Enter environment (ej: dev, prod): " projectenv
read -p "Enter github account name: " ghaccount
read -p "Enter github repo name: " ghrepo

# Names

role_name="${projectname}-role-${projectenv}-bootstrap"
policy_name="${projectname}-policy-${projectenv}-bootstrap"
s3_name="${projectname}-policy-${projectenv}-bootstrap"

# Create oidc

OIDC_ARN="arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):oidc-provider/token.actions.githubusercontent.com"
OIDC_FOUND=$(aws iam list-open-id-connect-providers --query "OpenIDConnectProviderList[?Arn=='$OIDC_ARN']" --output text)

if [ -z "$OIDC_FOUND" ]; then
  aws iam create-open-id-connect-provider \
    --url https://token.actions.githubusercontent.com \
    --client-id-list sts.amazonaws.com \
    --thumbprint-list "6938fd4d98bab03faadb97b34396831e3780aea1" \
    >/dev/null
  echo "OIDC provider created"
else
  echo "OIDC provider exists, skipping"
fi

# Create role

cat > trust_policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:${ghaccount}/${ghrepo}:*"
        }
      }
    }
  ]
}
EOF

if aws iam get-role --role-name "$role_name" >/dev/null 2>&1; then
  echo "Role exists, skipping"
else
  aws iam create-role --role-name "$role_name" --assume-role-policy-document file://trust_policy.json >/dev/null
  echo "Role created"
fi

rm trust_policy.json

cat > role_policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${projectname}-s3-{projectenv}-*",
        "arn:aws:s3:::${projectname}-s3-{projectenv}-*/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "dynamodb:*",
      "Resource": [
        "arn:aws:dynamodb:${AWS_REGION}:*:table/${projectname}-ddb-{projectenv}-*"
      ]
    }
  ]
}
EOF

aws iam put-role-policy --role-name "$role_name" --policy-name "$policy_name" --policy-document file://role_policy.json >/dev/null

rm role_policy.json

# Create s3

if aws s3api head-bucket --bucket "$s3_name" 2>/dev/null; then
  echo "Bucket exists, skipping"
else
  aws s3api create-bucket --bucket "$s3_name" --region "$AWS_REGION" --create-bucket-configuration LocationConstraint="$AWS_REGION"
  aws s3api put-public-access-block --bucket "$s3_name" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  aws s3api put-bucket-encryption --bucket "$s3_name" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
  echo "Bucket created"
fi

if aws s3api head-bucket --bucket "$s3_name" 2>/dev/null; then
  echo "Bucket exists, skipping"
else
  aws s3api create-bucket --bucket "$s3_name" --region "$AWS_REGION" --create-bucket-configuration LocationConstraint="$AWS_REGION" >/dev/null
  aws s3api put-public-access-block --bucket "$s3_name" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null
  aws s3api put-bucket-encryption --bucket "$s3_name" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' >/dev/null
  echo "Bucket created"
fi

echo "S3 name: $s3_name"
echo "Role name: $role_name"

