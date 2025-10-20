# SSH Key

resource "tls_private_key" "keypair" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "aws_keypair" {
  key_name   = local.keypair_name
  public_key = tls_private_key.keypair.public_key_openssh
}

resource "local_file" "keypair_save" {
  content              = tls_private_key.keypair.private_key_pem
  filename             = "${path.cwd}/${local.keypair_name}.pem"
  file_permission      = "0600"
  directory_permission = "0700"
}

# VPC

resource "aws_vpc" "main" {
  cidr_block                     = var.vpc_cidr
  enable_dns_support             = true
  enable_dns_hostnames           = true
  assign_generated_ipv6_cidr_block = var.vpc_ipv6_enable
  tags = {
    Name = "${var.project_name}-vpc"
  }
}