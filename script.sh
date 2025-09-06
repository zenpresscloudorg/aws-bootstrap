

# Security Groups

sg_test_id=$(aws ec2 describe-security-groups \
  --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=$sg_test_name" \
  --query "SecurityGroups[0].GroupId" --output text)

if [[ "$sg_test_id" != "None" && -n "$sg_test_id" ]]; then
  echo "Security Group $sg_test_name exists, skipping creation"
else
  sg_test_id=$(aws ec2 create-security-group \
    --group-name "$sg_test_name" \
    --description "All open (test)" \
    --vpc-id "$vpc_id" \
    --query "GroupId" --output text)
  echo "Security Group $sg_test_name created: $sg_test_id"
  aws ec2 authorize-security-group-ingress \
    --group-id "$sg_test_id" \
    --protocol -1 --port all --cidr 0.0.0.0/0 >/dev/null
  echo "Inbound rule ALL open for $sg_test_name"
fi

sg_natgw_id=$(aws ec2 describe-security-groups \
  --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=$sg_natgw_name" \
  --query "SecurityGroups[0].GroupId" --output text)
if [[ "$sg_natgw_id" != "None" && -n "$sg_natgw_id" ]]; then
  echo "Security Group $sg_natgw_name exists, skipping creation"
else
  sg_natgw_id=$(aws ec2 create-security-group \
    --group-name "$sg_natgw_name" \
    --description "All inbound blocked (NAT)" \
    --vpc-id "$vpc_id" \
    --query "GroupId" --output text)
  echo "Security Group $sg_natgw_name created: $sg_nsg_natgw_idat_id"
  echo "Inbound rule: ALL BLOCKED for $sg_natgw_name"
fi

# Public subnet


public_rt_id=$(aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=$vpc_id" "Name=tag:Name,Values=$public_rt_name" \
  --query "RouteTables[0].RouteTableId" \
  --output text)

if [[ "$public_rt_id" != "None" && -n "$public_rt_id" ]]; then
  echo "Public route table $public_rt_name exists, skipping creation"
else
  public_rt_id=$(aws ec2 create-route-table \
    --vpc-id "$vpc_id" \
    --query "RouteTable.RouteTableId" \
    --output text)
  aws ec2 create-tags --resources "$public_rt_id" --tags Key=Name,Value="$public_rt_name"
  echo "Public route table $public_rt_name created: $public_rt_id"

  aws ec2 create-route \
    --route-table-id "$public_rt_id" \
    --destination-cidr-block 0.0.0.0/0 \
    --gateway-id "$igw_id" >/dev/null
  echo "Added default route (0.0.0.0/0) via IGW $igw_id"
fi

for az in "${!public_subnet_ids[@]}"; do
  subnet_id="${public_subnet_ids[$az]}"
  # Comprobar si ya está asociada
  assoc_id=$(aws ec2 describe-route-tables \
    --route-table-ids "$public_rt_id" \
    --query "RouteTables[0].Associations[?SubnetId=='$subnet_id'].RouteTableAssociationId" \
    --output text)
  if [[ -n "$assoc_id" ]]; then
    echo "Subnet $subnet_id already associated to public route table, skipping"
  else
    aws ec2 associate-route-table \
      --route-table-id "$public_rt_id" \
      --subnet-id "$subnet_id" >/dev/null
    echo "Associated public subnet $subnet_id to route table $public_rt_id"
  fi
done

# Private subnet

private_rt_id=$(aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=$vpc_id" "Name=tag:Name,Values=$private_rt_name" \
  --query "RouteTables[0].RouteTableId" \
  --output text)

if [[ "$private_rt_id" != "None" && -n "$private_rt_id" ]]; then
  echo "Private route table $private_rt_name exists, skipping creation"
else
  private_rt_id=$(aws ec2 create-route-table \
    --vpc-id "$vpc_id" \
    --query "RouteTable.RouteTableId" \
    --output text)
  aws ec2 create-tags --resources "$private_rt_id" --tags Key=Name,Value="$private_rt_name"
  echo "Private route table $private_rt_name created: $private_rt_id"
fi

for az in "${!private_subnet_ids[@]}"; do
  subnet_id="${private_subnet_ids[$az]}"
  assoc_id=$(aws ec2 describe-route-tables \
    --route-table-ids "$private_rt_id" \
    --query "RouteTables[0].Associations[?SubnetId=='$subnet_id'].RouteTableAssociationId" \
    --output text)
  if [[ -n "$assoc_id" ]]; then
    echo "Subnet $subnet_id already associated to private route table, skipping"
  else
    aws ec2 associate-route-table \
      --route-table-id "$private_rt_id" \
      --subnet-id "$subnet_id" >/dev/null
    echo "Associated private subnet $subnet_id to route table $private_rt_id"
  fi
done

# Nat subnet

if [[ "$subnet_nat" =~ ^[yY]$ ]]; then

  # Nat GW

  ami_id=$(aws ec2 describe-images \
    --owners "amazon" \
    --filters "Name=name,Values=al2023-ami-minimal-arm64-*" "Name=state,Values=available" \
    --region "$account_region" \
    --query "Images | sort_by(@, &CreationDate)[-1].ImageId" \
    --output text)

  first_public_az="${azs[0]}"
  public_subnet_id="${public_subnet_ids[$first_public_az]}"

  cat > instance_natgw_userdata.sh <<EOF
  #!/bin/bash
  curl -fsSL https://tailscale.com/install.sh | sh
  tailscale up --authkey ${subnet_nat_tailscale}
  EOF

  instance_id=$(aws ec2 run-instances \
    --image-id "$ami_id" \
    --instance-type t4g.nano \
    --key-name "$keypair_name" \
    --security-group-ids "$sg_natgw_id" \
    --subnet-id "$public_subnet_id" \
    --associate-public-ip-address \
    --region "$account_region" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${instance_natgw_name}}]" \
    --user-data file://instance_natgw_userdata.sh \
    --query "Instances[0].InstanceId" \
    --output text)
  echo "Launched NAT instance $instance_id in subnet $public_subnet_id"

  rm instance_natgw_userdata.sh

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

  nat_rt_id=$(aws ec2 describe-route-tables \
    --filters "Name=vpc-id,Values=$vpc_id" "Name=tag:Name,Values=$nat_rt_name" \
    --query "RouteTables[0].RouteTableId" \
    --output text)

  if [[ "$nat_rt_id" != "None" && -n "$nat_rt_id" ]]; then
    echo "NAT route table $nat_rt_name exists, skipping creation"
  else
    nat_rt_id=$(aws ec2 create-route-table \
      --vpc-id "$vpc_id" \
      --query "RouteTable.RouteTableId" \
      --output text)
    aws ec2 create-tags --resources "$nat_rt_id" --tags Key=Name,Value="$nat_rt_name"
    echo "NAT route table $nat_rt_name created: $nat_rt_id"
    # Aquí puedes poner la ruta que necesites para la subnet NAT
  fi

  for az in "${!nat_subnet_ids[@]}"; do
    subnet_id="${nat_subnet_ids[$az]}"
    assoc_id=$(aws ec2 describe-route-tables \
      --route-table-ids "$nat_rt_id" \
      --query "RouteTables[0].Associations[?SubnetId=='$subnet_id'].RouteTableAssociationId" \
      --output text)
    if [[ -n "$assoc_id" ]]; then
      echo "Subnet $subnet_id already associated to NAT route table, skipping"
    else
      aws ec2 associate-route-table \
        --route-table-id "$nat_rt_id" \
        --subnet-id "$subnet_id" >/dev/null
      echo "Associated NAT subnet $subnet_id to route table $nat_rt_id"
    fi
  done
fi

# Public domains
if [[ -n "${public_domains[*]}" ]]; then
  for domain in "${public_domains[@]}"; do
    hz_id=$(aws route53 list-hosted-zones-by-name --dns-name "$domain." \
      --query "HostedZones[?Name=='$domain.'] | [?Config.PrivateZone==\`false\`].Id" \
      --output text | head -n 1)
    if [[ -n "$hz_id" ]]; then
      echo "Public domain $domain: already exists, skipping"
    else
      aws route53 create-hosted-zone \
        --name "$domain" \
        --caller-reference "$(date +%s)-$domain" \
        --query "HostedZone.Id" \
        --output text >/dev/null
      echo "Public domain $domain: created"
    fi
  done
fi

# Private domains

if [[ -n "${private_domains[*]}" ]]; then
  for domain in "${private_domains[@]}"; do
    hz_id=$(aws route53 list-hosted-zones-by-name --dns-name "$domain." \
      --query "HostedZones[?Name=='$domain.' && Config.PrivateZone==\`true\`].Id" \
      --output text | head -n 1)
    if [[ -n "$hz_id" ]]; then
      echo "Private domain $domain: already exists, skipping"
    else
      aws route53 create-hosted-zone \
        --name "$domain" \
        --vpc VPCRegion=$account_region,VPCId="$vpc_id" \
        --hosted-zone-config PrivateZone=true \
        --caller-reference "$(date +%s)-$domain" \
        --query "HostedZone.Id" --output text >/dev/null
      echo "Private domain $domain: created"
    fi
  done
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
echo "VPC Id: $vpc_id"
echo "Security Group test ID: $sg_test_id"
if [[ -n "${public_domains[*]}" ]]; then
  for domain in "${public_domains[@]}"; do
    hz_id=$(aws route53 list-hosted-zones-by-name --dns-name "$domain." \
      --query "HostedZones[?Name=='$domain.'] | [?Config.PrivateZone==\`false\`].Id" \
      --output text | head -n 1)
    hz_id="${hz_id##*/}"
    ns_servers=$(aws route53 get-hosted-zone --id "$hz_id" \
      --query "DelegationSet.NameServers" --output text)
    echo "Public domain: $domain | Hosted Zone ID: $hz_id | Nameservers: $ns_servers"
  done
fi
if [[ -n "${private_domains[*]}" ]]; then
  for domain in "${private_domains[@]}"; do
    hz_id=$(aws route53 list-hosted-zones-by-name --dns-name "$domain." \
      --query "HostedZones[?Name=='$domain.' && Config.PrivateZone==\`true\`].Id" \
      --output text | head -n 1)
    hz_id="${hz_id##*/}"
    echo "Private domain: $domain | Hosted Zone ID: $hz_id"
  done
fi