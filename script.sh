#!/bin/bash

read -p "Enter project name: " projectname
read -p "Enter github account name: " ghaccount
read -p "Enter github repo name: " ghrepo
read -p "Enter aws account name: " awsacct

prefix="bootstrap-${projectname}"
rol_name="${prefix}-role"
bucket_name="${prefix}-s3-$(date +%s)"
policy_name="${prefix}-policy"

# Create oidc

OIDC_ARN="arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):oidc-provider/token.actions.githubusercontent.com"
OIDC_FOUND=$(aws iam list-open-id-connect-providers --query "OpenIDConnectProviderList[?Arn=='$OIDC_ARN']" --output text)

if [ -z "$OIDC_FOUND" ]; then
  aws iam create-open-id-connect-provider \
    --url https://token.actions.githubusercontent.com \
    --client-id-list sts.amazonaws.com \
    --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
  echo "OIDC provider created"
else
  echo "OIDC provider found, skipping"
fi

# Create role

cat > role_policy.json <<EOF
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

aws iam create-role --role-name "$prefix" --assume-role-policy-document file://role_policy.json




























# 1. Crear bucket S3 privado y encriptado
aws s3api create-bucket --bucket "$bucket_name" --region "$(aws configure get region)" --create-bucket-configuration LocationConstraint="$(aws configure get region)"
aws s3api put-public-access-block --bucket "$bucket_name" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket "$bucket_name" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# 2. Crear rol para Github Actions (solo acceso al bucket)




cat > s3-access-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
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

aws iam put-role-policy --role-name "$rol_name" --policy-name "s3-$proyecto-access" --policy-document file://s3-access-policy.json

rm trust-policy.json s3-access-policy.json




echo "Bucket: $bucket_name"
echo "Rol: $rol_name"

