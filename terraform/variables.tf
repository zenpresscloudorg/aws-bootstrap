variable "project_name" {
  description = "Project name"
  type        = string
  default     = "demo"
}

variable "project_environment" {
  description = "Project environment (dev, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "prod"], var.project_environment)
    error_message = "project_environment must be either 'dev' or 'prod'."
  }
}

# VPC variables
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "vpc_ipv6_enable" {
  description = "Enable IPv6 support in the VPC"
  type        = bool
  default     = true
}

variable "hostedzone_public" {
  description = "Public DNS zones"
  type        = string
}

variable "hostedzone_private" {
  description = "Private DNS zones"
  type        = string
}

variable "tailscale_auth_key" {
  description = "Authentication key for Tailscale."
  type        = string
}

variable "gh_org" {
  description = "GitHub organization"
  type        = string
}

variable "gh_dispatcher_token" {
  description = "Token for GitHub Actions dispatching"
  type        = string
  sensitive   = true
}

variable "gh_runner_token" {
  description = "Token for GitHub Actions runners"
  type        = string
  sensitive   = true
}