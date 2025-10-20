# Outputs de información general
output "aws_account_id" {
  description = "ID de la cuenta de AWS"
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "Región de AWS actual"
  value       = data.aws_region.current.name
}

output "availability_zones" {
  description = "Zonas de disponibilidad en la región"
  value       = data.aws_availability_zones.available.names
}

output "project_info" {
  description = "Información del proyecto"
  value = {
    name        = var.project_name
    environment = var.project_environment
    region      = var.aws_region
  }
}