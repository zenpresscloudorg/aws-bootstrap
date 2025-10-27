
# NatGW Instance

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
        Sid     = "AllowRunnerListBucket"
        Effect  = "Allow"
        Principal = { AWS = aws_iam_role.role_ghrunner.arn }
        Action  = [
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::${aws_s3_bucket.s3_tfstate.bucket}"
      },
      {
        Sid     = "AllowRunnerObjectRW"
        Effect  = "Allow"
        Principal = { AWS = aws_iam_role.role_ghrunner.arn }
        Action  = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "arn:aws:s3:::${aws_s3_bucket.s3_tfstate.bucket}/*"
      },
      {
        Sid     = "DenyAllExceptRunner"
        Effect  = "Deny"
        NotPrincipal = { AWS = aws_iam_role.role_ghrunner.arn }
        Action  = "s3:*"
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.s3_tfstate.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.s3_tfstate.bucket}/*"
        ]
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