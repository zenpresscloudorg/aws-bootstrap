// Outputs requested by user

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of all public subnets"
  value       = [for s in aws_subnet.public_subnet : s.id]
}

output "private_subnet_ids" {
  description = "IDs of all private subnets"
  value       = [for s in aws_subnet.private_subnet : s.id]
}

output "sg_demo_id" {
  description = "ID of the demo security group (sg_test)"
  value       = aws_security_group.sg_test.id
}

output "route53_public_zone_id" {
  description = "ID of the public Route53 hosted zone"
  value       = aws_route53_zone.public.zone_id
}

output "route53_private_zone_id" {
  description = "ID of the private Route53 hosted zone"
  value       = aws_route53_zone.private.zone_id
}

output "route53_public_nameservers" {
  description = "Nameservers of the public hosted zone"
  value       = aws_route53_zone.public.name_servers
}

output "route53_private_nameservers" {
  description = "Nameservers of the private hosted zone"
  value       = aws_route53_zone.private.name_servers
}

output "secret_keypair" {
  description = "ID of the AWS Secrets Manager secret storing the SSH keypair (private and public)"
  value       = aws_secretsmanager_secret.secret_keypair_main.id
}

output "lambdaurl_ghdispatcher" {
  description = "URL para invocar la función Lambda ghdispatcher"
  value       = aws_lambda_function_url.lambdaurl_ghdispatcher.function_url
}