# Random strings

resource "random_string" "randomstring_ghdispatcher" {
  length  = 8
  upper   = true
  lower   = true
  numeric = true
  special = false
}

# SSH Key

resource "tls_private_key" "keypair" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "aws_keypair" {
  key_name   = local.keypair_main_name
  public_key = tls_private_key.keypair.public_key_openssh
}

# Secrets

resource "aws_secretsmanager_secret" "secret_keypair_main" {
  name        = local.secret_keypair_main_name
}

resource "aws_secretsmanager_secret" "secret_ghdispatcher" {
  name        = local.secret_ghdispatcher_name
}

resource "aws_secretsmanager_secret_version" "secretvalue_keypair_main" {
  secret_id     = aws_secretsmanager_secret.secret_keypair_main.id
  secret_string = jsonencode({
    keypair_private = tls_private_key.keypair.private_key_pem
    keypair_public = tls_private_key.keypair.public_key_openssh
  })
}

resource "aws_secretsmanager_secret_version" "secretvalue_ghdispatcher" {
  secret_id     = aws_secretsmanager_secret.secret_ghdispatcher.id
  secret_string = jsonencode({
    gh_dispatcher_token = var.gh_dispatcher_token
    api_auth = random_string.randomstring_ghdispatcher.result
  })
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
  description = "ec2_natwg"
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

# NatGW Instance

resource "local_file" "userdata_natgw" {
  content  = templatefile("${path.module}/src/userdata/natgw.sh", {
    AUTH_KEY         = var.tailscale_auth_key,
    HOSTNAME         = local.ec2_natwg_name,
    ADVERTISE_ROUTES = join(",", local.private_subnets_cidr),
    DNSMASQ_SERVERS  = local.dnsmasq_servers
  })
  filename = "${path.module}/tmp/userdata_natgw_rendered.sh"
}

resource "aws_instance" "ec2_natwg" {
  ami                    = local.instances_ami
  instance_type          = local.instances_type
  key_name               = aws_key_pair.aws_keypair.key_name
  subnet_id              = aws_subnet.public_subnet[local.azs[0]].id
  vpc_security_group_ids = [aws_security_group.sg_natgw.id]
  user_data              = file(local_file.userdata_natgw.filename)
  root_block_device {
    volume_type = "gp3"
    tags = {
      Name = local.ebs_natgw_name
    }
  }
  tags = {
     Name = local.ec2_natwg_name
  }
  source_dest_check = false
}

resource "aws_internet_gateway" "igw_main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = local.igw_name
  }
}

# Route tables

resource "aws_route_table" "rt_public" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = local.rt_public_name
  }
}

resource "aws_route" "route_public_main" {
  route_table_id         = aws_route_table.rt_public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw_main.id
}

resource "aws_route_table_association" "rtassoc_public" {
  for_each = aws_subnet.public_subnet
  subnet_id      = each.value.id
  route_table_id = aws_route_table.rt_public.id
}

resource "aws_route_table" "rt_private" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = local.rt_private_name
  }
}

resource "aws_route" "route_private_main" {
  route_table_id         = aws_route_table.rt_private.id
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_instance.ec2_natwg.primary_network_interface_id
}

resource "aws_route_table_association" "rtassoc_private" {
  for_each = aws_subnet.private_subnet
  subnet_id      = each.value.id
  route_table_id = aws_route_table.rt_private.id
}

# Runner

resource "aws_iam_role" "role_ghrunner" {
  name = local.role_ec2_ghrunner_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "policy_ghrunner" {
  name        = local.policy_ec2_ghrunner_name
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "s3:*"
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.s3_tfstate.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.s3_tfstate.bucket}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = "dynamodb:*"
        Resource = [
          "arn:aws:dynamodb:${data.aws_region.current.name}:*:table/${var.project_name}-${var.project_environment}-ddb-*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ghrunner" {
  role       = aws_iam_role.role_ghrunner.name
  policy_arn = aws_iam_policy.policy_ghrunner.arn
}

resource "aws_iam_instance_profile" "ghrunner" {
  name = local.instanceprofile_ghrunner
  role = aws_iam_role.role_ghrunner.name
}

resource "local_file" "userdata_ghrunner" {
  content  = templatefile("${path.module}/src/userdata/ghrunner.sh", {
    GH_ORG = var.gh_org
    GH_RUNNER_TOKEN = var.gh_runner_token
    GH_RUNNER_NAME = local.ec2_ghrunner_name
  })
  filename = "${path.module}/tmp/userdata_ghrunner_rendered.sh"
}

resource "aws_instance" "instance_ghrunner" {
  ami                    = local.instances_ami
  instance_type          = local.instances_type
  key_name               = aws_key_pair.aws_keypair.key_name
  subnet_id              = aws_subnet.private_subnet[local.azs[0]].id
  vpc_security_group_ids = [aws_security_group.sg_ghrunner.id]
  user_data              = file(local_file.userdata_ghrunner.filename)
  iam_instance_profile   = aws_iam_instance_profile.ghrunner.name
  root_block_device {
    volume_type = locals.instances_disk
    tags = {
      Name = local.ebs_ghrunner_name
    }
  }
  tags = {
     Name = local.ec2_ghrunner_name
  }
}

# S3 Terraform bucket

resource "aws_s3_bucket" "s3_tfstate" {
  bucket = local.s3_tfstate_name
}

resource "aws_s3_bucket_versioning" "s3versioning_tfstate" {
  bucket = aws_s3_bucket.s3_tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3encryption_tfstate" {
  bucket = aws_s3_bucket.s3_tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "policy_s3_tfstate" {
  bucket = aws_s3_bucket.s3_tfstate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AllowOnlySpecificRole"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.role_ghrunner.arn
        }
        Action = "s3:*"
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.s3_tfstate.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.s3_tfstate.bucket}/*"
        ]
      },
      {
        Sid = "DenyAllOtherPrincipals"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.s3_tfstate.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.s3_tfstate.bucket}/*"
        ]
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = aws_iam_role.role_ghrunner.arn
          }
        }
      }
    ]
  })
}

# Lambda dispatcher

data "archive_file" "zip_lambda_ghdispatcher" {
  type        = "zip"
  source_dir  = "${path.module}/src/lambda/ghdispatcher"
  output_path = "${path.module}/tmp/lambda_ghdispatcher.zip"
}

resource "aws_iam_role" "role_lambda_ghdispatcher" {
  name               = local.role_lambda_ghdispatcher_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
      Effect    = "Allow"
    }]
  })
}

resource "aws_iam_policy" "policy_lambda_ghdispatcher" {
  name   = local.policy_lambda_ghdispatcher_name
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "lambda:InvokeFunctionUrl"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "policyattach_lambda_ghdispatcher" {
  role       = aws_iam_role.role_lambda_ghdispatcher.name
  policy_arn = aws_iam_policy.policy_lambda_ghdispatcher.arn
}

resource "aws_iam_role_policy_attachment" "policyattach_lambda_ghdispatcher_basicexecution" {
  role       = aws_iam_role.role_lambda_ghdispatcher.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "policy_secret_ghdispatcher" {
  name   = local.policy_secret_ghdispatcher_name
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "secretsmanager:GetSecretValue"
        ],
        Resource = aws_secretsmanager_secret.secret_ghdispatcher.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "policyattach_ghdispatcher_secrets" {
  role       = aws_iam_role.role_lambda_ghdispatcher.name
  policy_arn = aws_iam_policy.policy_secret_ghdispatcher.arn
}

resource "aws_lambda_function" "lambda_ghdispatcher" {
  provider      = aws.lambda_eu_west_1
  function_name = locals.lambda_ghdispatcher_name
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  role          = aws_iam_role.role_lambda_ghdispatcher.arn
  filename      = data.archive_file.zip_lambda_ghdispatcher.output_path
  timeout       = 10
  environment {
    variables = {
      GH_ORG   = var.gh_org
      SECRET_GHDISPATCHER = aws_secretsmanager_secret.secret_ghdispatcher.id
    }
  }
}

resource "aws_lambda_function_url" "lambdaurl_ghdispatcher" {
  provider           = aws.lambda_eu_west_1
  function_name      = aws_lambda_function.lambda_ghdispatcher.function_name
  authorization_type = "NONE"
}

# Hostedzone

resource "aws_route53_zone" "public" {
  name = var.hostedzone_public
}

resource "aws_route53_zone" "private" {
  name = var.hostedzone_private
  vpc {
    vpc_id     = aws_vpc.main.id
    vpc_region = data.aws_region.current.name
  }
}