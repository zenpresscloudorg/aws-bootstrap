
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