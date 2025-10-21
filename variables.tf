
variable "project_name" {
  description = "Nombre del proyecto"
  type        = string
  default     = "demo"
}

variable "project_environment" {
  description = "Entorno del proyecto (dev, staging, prod)"
  type        = string
  default     = "prod"
}

# Variables de VPC
variable "vpc_cidr" {
  description = "CIDR block para la VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_ipv6_enable" {
  description = "Habilitar soporte IPv6 en la VPC"
  type        = bool
  default     = true
}

variable "vpc_subnet_private_tskey" {
  description = "Clave para identificar subnets privadas"
  type        = string
  default     = "demo"
}

variable "hostedzones_public" {
  description = "Lista de zonas DNS públicas"
  type        = list(string)
  default     = ["demo.demo"]
}

variable "hostedzones_private" {
  description = "Lista de zonas DNS privadas"
  type        = list(string)
  default     = ["demo.demo"]
}

variable "tailscale_auth_key" {
  description = "Llave de autenticación para Tailscale."
  type        = string
}

variable "github_org" {
  description = "Organización de GitHub"
  type        = string
  default     = "demo.demo"
}

variable "github_personal_token" {
description = "Token para GitHub Actions runners"
  type        = string
  sensitive   = true
  default     = "demo"
}