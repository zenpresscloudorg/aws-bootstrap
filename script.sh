#!/bin/bash

# Questions

read -p "Enter project name: " projectname
read -p "Enter environment (ej: dev, prod): " projectenv
read -p "Do you want to add project domain/s to route53 (public domain/s) (optional) ? (y/n): " add_domains

if [[ "$add_domains" =~ ^[yY]$ ]]; then
  echo "Enter one or more domains separated by spaces (only public domains):"
  read -a projectdomains
  echo "Domains to be created: ${projectdomains[@]}"
fi

read -p "Enter github account name: " ghaccount
read -p "Enter github repo name: " ghrepo

# Variables

role_name="${projectname}-role-${projectenv}-bootstrap"
policy_name="${projectname}-policy-${projectenv}-bootstrap"
s3_name="${projectname}-s3-${projectenv}-bootstrap"
keypair_name="${projectname}-keypair"
keypair_file="${key_name}.pem"
declare -A hosted_zone_ids

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
        "arn:aws:s3:::${projectname}-s3-${projectenv}-*",
        "arn:aws:s3:::${projectname}-s3-${projectenv}-*/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "dynamodb:*",
      "Resource": [
        "arn:aws:dynamodb:${AWS_REGION}:*:table/${projectname}-ddb-${projectenv}-*"
      ]
    }
  ]
}
EOF

aws iam put-role-policy --role-name "$role_name" --policy-name "$policy_name" --policy-document file://role_policy.json >/dev/null
rm role_policy.json

# Create s3

cat > s3_policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOnlySpecificRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "$(aws iam get-role --role-name "$role_name" --query "Role.Arn" --output text)"
      },
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${s3_name}",
        "arn:aws:s3:::${s3_name}/*"
      ]
    },
    {
      "Sid": "DenyAllOtherPrincipals",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${s3_name}",
        "arn:aws:s3:::${s3_name}/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "$role_arn"
        }
      }
    }
  ]
}
EOF

if aws s3api head-bucket --bucket "$s3_name" 2>/dev/null; then
  echo "Bucket exists, skipping"
else
  aws s3api create-bucket --bucket "$s3_name" --region "$AWS_REGION" --create-bucket-configuration LocationConstraint="$AWS_REGION" >/dev/null 2>&1
  aws s3api put-public-access-block --bucket "$s3_name" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null 2>&1
  aws s3api put-bucket-encryption --bucket "$s3_name" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' >/dev/null 2>&1
  aws s3api put-bucket-versioning --bucket "$s3_name" --versioning-configuration Status=Enabled >/dev/null 2>&1
  aws s3api put-bucket-policy --bucket "$s3_name" --policy file://s3_policy.json >/dev/null 2>&1
  echo "Bucket created"
fi

rm s3_policy.json

# Keypair

if aws ec2 describe-key-pairs --key-names "$keypair_name" >/dev/null 2>&1; then
  echo "Key pair exists, skipping"
else
  aws ec2 create-key-pair --key-name "$keypair_name" --query "KeyMaterial" --output text > "$keypair_file"

fi

# Domains

if [[ -n "${projectdomains[*]}" ]]; then
  for domain in "${projectdomains[@]}"; do
    hz_id=$(aws route53 list-hosted-zones-by-name --dns-name "$domain." \
      --query "HostedZones[?Name=='$domain.'] | [?Config.PrivateZone==\`false\`].Id" \
      --output text | head -n 1)

    if [[ -n "$hz_id" ]]; then
      echo "Hosted zone for $domain exists, skipping"
    else
      hosted_zone_id=$(aws route53 create-hosted-zone \
        --name "$domain" \
        --caller-reference "$(date +%s)-$domain" \
        --query "HostedZone.Id" \
        --output text)
      hosted_zone_id="${hosted_zone_id##*/}"
      hosted_zone_ids["$domain"]="$hosted_zone_id"
      echo "Hosted zone for $domain created."
    fi
  done
fi

# Echos

echo "S3 name: $s3_name"
echo "Role name: $role_name"
echo "Keypair location: $(realpath "$keypair_file") PLEASE DOWNLOAD PEM"
if [[ -n "${projectdomains[*]}" ]]; then
  for domain in "${projectdomains[@]}"; do
    ns_servers=$(aws route53 get-hosted-zone --id "${hosted_zone_ids[$domain]}" \
      --query "DelegationSet.NameServers" --output text)
    echo "Domain $domain added to Route53."
    echo "Nameservers:"
    echo "$ns_servers"
    echo ""
  done
fi

