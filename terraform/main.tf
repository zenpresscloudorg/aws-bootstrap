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

# Subnets

resource "aws_subnet" "public_subnet" {
  for_each = { for idx, az in local.azs : az => {
    cidr_block = local.public_subnets_cidr[idx]
    name       = local.public_subnet_names[idx]
  } }
  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value.cidr_block
  availability_zone       = each.key
  map_public_ip_on_launch = true
  tags = {
    Name = each.value.name
  }
}

resource "aws_subnet" "private_subnet" {
  for_each = { for idx, az in local.azs : az => {
    cidr_block = local.private_subnets_cidr[idx]
    name       = local.private_subnet_names[idx]
  } }
  vpc_id            = aws_vpc.main.id
  cidr_block        = each.value.cidr_block
  availability_zone = each.key
  map_public_ip_on_launch = false
  tags = {
    Name = each.value.name
  }
}

# Security groups

resource "aws_security_group" "sg_test" {
  name        = local.sg_test_name
  description = "test"
  vpc_id      = aws_vpc.main.id
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = local.sg_test_name
  }
}

resource "aws_security_group" "sg_natgw" {
  name        = local.sg_natgw_name
  description = "ec2-natgw"
  vpc_id      = aws_vpc.main.id
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = local.private_subnets_cidr
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = local.sg_natgw_name
  }
}

resource "aws_security_group" "sg_ghrunner" {
  name        = local.sg_ghrunner_name
  description = "ec2-ghrunner"
  vpc_id      = aws_vpc.main.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = local.sg_ghrunner_name
  }
}

