#!/bin/bash

# Questions

read -p "Enter project name: " projectname
read -p "Enter environment (ej: dev, prod): " projectenv
read -p "Do you want to add project domain/s to route53 (public domain/s) (optional) ? (y/n): " add_domains
read -p "Enter CIDR block for the VPC (default 10.0.0.0/16): " vpc_cidr
read -p "Do you want to enable IPv6 for the VPC? (y/n): " vpc_ipv6
read -p "Do you want to create a private subnet with NAT (optional)? (y/n): " subnet_nat
read -p "Do you want to create a private domain in Route53 for accessing your resources (e.g. servers)? (y/n): " subnet_private_domain

if [[ "$subnet_private_domain" =~ ^[yY]$ ]]; then
  read -p "Enter the private domain name (e.g. internal.example.com): " subnet_private_domain_name
  echo "Private domain to be created: $subnet_private_domain_name"
fi

if [[ "$add_domains" =~ ^[yY]$ ]]; then
  echo "Enter one or more domains separated by spaces (only public domains):"
  read -a projectdomains
  echo "Domains to be created: ${projectdomains[@]}"
fi

if [[ "$subnet_nat" =~ ^[yY]$ ]]; then
  echo "A private subnet with NAT will be created."
  read -s -p "Enter your Tailscale API key: " subnet_nat_tailscale
  echo
fi

read -p "Enter github account name: " ghaccount
read -p "Enter github repo name: " ghrepo



############# TEST


projectname="test"
projectenv="dev"
add_domains="y"
vpc_cidr="10.0.0.0/16"
vpc_ipv6="y"
subnet_nat="y"
subnet_private_domain="y"
subnet_private_domain_name="hola.local"
projectdomains="sdfsdfdfgfhdfhfgh.com"
subnet_nat_tailscale="1235"
ghaccount="test"
ghrepo="test"

# End questions

echo ""
echo "--------------------------"
echo "Starting"
echo "--------------------------"
echo ""
sleep 3

# Variables

account_name=$(aws sts get-caller-identity --query Account --output text)
account_region=$(echo $AWS_REGION);
azs=($(aws ec2 describe-availability-zones --filters Name=region-name,Values=$(account_region) --query "AvailabilityZones[].ZoneName" --output text))
vpc_name="${projectname}-vpc-${projectenv}-bootstrap"
role_name="${projectname}-role-${projectenv}-bootstrap"
policy_name="${projectname}-policy-${projectenv}-bootstrap"
s3_name="${projectname}-s3-${projectenv}-bootstrap"
keypair_name="${projectname}-keypair-${projectenv}-bootstrap"
keypair_file="${keypair_name}.pem"
declare -A hosted_zone_ids
declare -A public_subnet_ids
declare -A private_subnet_ids
declare -A nat_subnet_ids

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
        "Federated": "arn:aws:iam::$account_name:oidc-provider/token.actions.githubusercontent.com"
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

role_arn=$(aws iam get-role --role-name "$role_name" --query "Role.Arn" --output text)

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
        "AWS": "$role_arn"
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
      hz_id="${hz_id##*/}"
      hosted_zone_ids["$domain"]="$hz_id"
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

# VPC

vpc_id=$(aws ec2 create-vpc \
  --cidr-block "$vpc_cidr" \
  --query "Vpc.VpcId" \
  --output text)

aws ec2 create-tags --resources "$vpc_id" --tags Key=Name,Value="$vpc_name"

if [[ "$vpc_ipv6" =~ ^[yY]$ ]]; then
  ipv6_assoc=$(aws ec2 associate-vpc-cidr-block --vpc-id "$vpc_id" --amazon-provided-ipv6-cidr-block --query "Ipv6CidrBlockAssociation.Ipv6CidrBlock" --output text)
  echo "IPv6 enabled for VPC. IPv6 CIDR block: $ipv6_assoc"
else
  echo "IPv6 not enabled for VPC."
fi

# Public subnet

for i in "${!azs[@]}"; do
  az="${azs[$i]}"
  subnet_name="${projectname}-subnet-public-${projectenv}-${az}"
  existing_subnet_id=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=$subnet_name" "Name=vpc-id,Values=$vpc_id" "Name=availability-zone,Values=$az" \
    --query "Subnets[0].SubnetId" --output text)
  if [[ "$existing_subnet_id" != "None" && -n "$existing_subnet_id" ]]; then
    public_subnet_ids["$az"]="$existing_subnet_id"
    echo "Public subnet for $az exists, skipping creation"
  else
    subnet_cidr="10.0.$((i+1)).0/24"
    subnet_id=$(aws ec2 create-subnet \
      --vpc-id "$vpc_id" \
      --cidr-block "$subnet_cidr" \
      --availability-zone "$az" \
      --query "Subnet.SubnetId" \
      --output text)
    aws ec2 create-tags --resources "$subnet_id" --tags Key=Name,Value="$subnet_name"
    public_subnet_ids["$az"]="$subnet_id"
    echo "Public subnet for $az created"
  fi
done


igw_id=$(aws ec2 create-internet-gateway --query "InternetGateway.InternetGatewayId" --output text)
aws ec2 attach-internet-gateway --vpc-id "$vpc_id" --internet-gateway-id "$igw_id"
aws ec2 create-tags --resources "$igw_id" --tags Key=Name,Value="${projectname}-igw-${projectenv}-bootstrap"

# Private subnet

for i in "${!azs[@]}"; do
  az="${azs[$i]}"
  subnet_name="${projectname}-subnet-private-${projectenv}-${az}"
  existing_subnet_id=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=$subnet_name" "Name=vpc-id,Values=$vpc_id" "Name=availability-zone,Values=$az" \
    --query "Subnets[0].SubnetId" --output text)
  if [[ "$existing_subnet_id" != "None" && -n "$existing_subnet_id" ]]; then
    private_subnet_ids["$az"]="$existing_subnet_id"
    echo "Private subnet for $az exists, skipping creation"
  else
    subnet_cidr="10.0.$((100+i+1)).0/24"
    subnet_id=$(aws ec2 create-subnet \
      --vpc-id "$vpc_id" \
      --cidr-block "$subnet_cidr" \
      --availability-zone "$az" \
      --query "Subnet.SubnetId" \
      --output text)
    aws ec2 create-tags --resources "$subnet_id" --tags Key=Name,Value="$subnet_name"
    private_subnet_ids["$az"]="$subnet_id"
    echo "Private subnet for $az created"
  fi
done

# Nat subnet

if [[ "$subnet_nat" =~ ^[yY]$ ]]; then
  for i in "${!azs[@]}"; do
    az="${azs[$i]}"
    subnet_name="${projectname}-subnet-nat-${projectenv}-${az}"
    existing_subnet_id=$(aws ec2 describe-subnets \
      --filters "Name=tag:Name,Values=$subnet_name" "Name=vpc-id,Values=$vpc_id" "Name=availability-zone,Values=$az" \
      --query "Subnets[0].SubnetId" --output text)
    if [[ "$existing_subnet_id" != "None" && -n "$existing_subnet_id" ]]; then
      nat_subnet_ids["$az"]="$existing_subnet_id"
      echo "NAT subnet for $az exists, skipping creation"
    else
      subnet_cidr="10.0.$((200+i+1)).0/24"
      subnet_id=$(aws ec2 create-subnet \
        --vpc-id "$vpc_id" \
        --cidr-block "$subnet_cidr" \
        --availability-zone "$az" \
        --query "Subnet.SubnetId" \
        --output text)
      aws ec2 create-tags --resources "$subnet_id" --tags Key=Name,Value="$subnet_name"
      nat_subnet_ids["$az"]="$subnet_id"
      echo "NAT subnet for $az created"
    fi
  done
fi

# Private domain

if [[ "$subnet_private_domain" =~ ^[yY]$ ]]; then
  private_zone_id=$(aws route53 list-hosted-zones-by-name --dns-name "$subnet_private_domain_name." \
    --query "HostedZones[?Name=='$subnet_private_domain_name.' && Config.PrivateZone==\`true\`].Id" \
    --output text | head -n 1)
  if [[ -n "$private_zone_id" ]]; then
    private_zone_id="${private_zone_id##*/}"
    private_zone_msg="Private hosted zone for $subnet_private_domain_name exists, skipping"
  else
    private_zone_id=$(aws route53 create-hosted-zone \
      --name "$subnet_private_domain_name" \
      --vpc VPCRegion=$account_region,VPCId="$vpc_id" \ 
      --hosted-zone-config PrivateZone=true \
      --caller-reference "$(date +%s)-$subnet_private_domain_name" \
      --query "HostedZone.Id" --output text)
    private_zone_id="${private_zone_id##*/}"
    private_zone_msg="Private hosted zone created: $subnet_private_domain_name"
  fi
fi

# Echos
echo ""
echo "--------------------------"
echo "Results"
echo "--------------------------"
echo ""

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
echo "VPC created: $vpc_id"
if [[ "$subnet_private_domain" =~ ^[yY]$ ]]; then
  echo "$private_zone_msg"
else
  echo "No private hosted zone was created."
fi