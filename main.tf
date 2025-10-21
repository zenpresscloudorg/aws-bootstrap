locals {
  dnsmasq_servers = join("\n", [for domain in var.hostedzones_private : "server=/${domain}/$ROUTE53_RESOLVER"])
}
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
  Name = local.vpc_name
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

# Internet Gateway


resource "local_file" "natgw_user_data" {
  content  = templatefile("${path.module}/src/natgw_instance_userdata.sh", {
    AUTH_KEY         = var.tailscale_auth_key,
    HOSTNAME         = local.natgw_instance_name,
    ADVERTISE_ROUTES = join(",", local.private_subnets_cidr),
  DNSMASQ_SERVERS  = local.dnsmasq_servers
  })
  filename = "${path.module}/tmp/natgw_instance_userdata_rendered.sh"
}

resource "aws_instance" "natgw" {
  ami                    = local.instances_ami
  instance_type          = local.instances_type
  key_name               = aws_key_pair.aws_keypair.key_name
  subnet_id              = aws_subnet.public_subnet[local.azs[0]].id
  vpc_security_group_ids = [aws_security_group.sg_natgw.id]
  user_data              = file(local_file.natgw_user_data.filename)
  root_block_device {
    volume_type = "gp3"
    tags = {
      Name = local.natgw_ebs_name
    }
  }
  tags = {
    Name = local.natgw_instance_name
  }
  source_dest_check = false
}

# Elastic IP para NAT Gateway
resource "aws_eip" "natgw" {
  instance = aws_instance.natgw.id
  tags = {
    Name = local.natgw_instance_name
  }
}

resource "aws_internet_gateway" "igw_main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = local.igw_name
  }
}

# NatGW Instance

