variable "project_name" {
  description = "Project name"
  type        = string
  default     = "demo"
}

variable "project_environment" {
  description = "Project environment (dev, staging, prod)"
  type        = string
}

# VPC variables
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_ipv6_enable" {
  description = "Enable IPv6 support in the VPC"
  type        = bool
  default     = true
}

variable "vpc_subnet_private_tskey" {
  description = "Key to identify private subnets"
  type        = string
}

variable "hostedzones_public" {
  description = "List of public DNS zones"
  type        = list(string)
}

variable "hostedzones_private" {
  description = "List of private DNS zones"
  type        = list(string)
}

variable "tailscale_auth_key" {
  description = "Authentication key for Tailscale."
  type        = string
}

variable "github_org" {
  description = "GitHub organization"
  type        = string
}

variable "github_pat" {
  description = "Token for GitHub Actions runners"
  type        = string
  sensitive   = true
}