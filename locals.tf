
locals {
  # Secrets
  secret_keypair_main_name = "${var.project_name}-bootstrap-${var.project_environment}-secret-keypair-main"
  secret_ghdispatcher_name = "${var.project_name}-bootstrap-${var.project_environment}-secret-ghdispatcher"

  # S3
  s3_tfstate_name = "${var.project_name}-bootstrap-${var.project_environment}-s3-tfstate"

  # Roles & policies
  role_ec2_ghrunner_name   = "${var.project_name}-${var.project_environment}-bootstrap-role-ec2-ghrunner"
  policy_ec2_ghrunner_name = "${var.project_name}-bootstrap-${var.project_environment}-policy-ec2-ghrunner"
  role_lambda_ghdispatcher_name   = "${var.project_name}-${var.project_environment}-bootstrap-role-lambda-ghdispatcher"
  policy_lambda_ghdispatcher_name = "${var.project_name}-bootstrap-${var.project_environment}-bootstrap-policy-lambda-ghdispatcher"
  policy_secret_ghdispatcher_name = "${var.project_name}-bootstrap-${var.project_environment}-bootstrap-policy-secret-ghdispatcher"

  # Lambdas
  lambda_ghdispatcher_name = "${var.project_name}-bootstrap-${var.project_environment}-lambda-ghdispatcher"

  # Instances
  instances_ami        = "ami-0cd0767d8ed6ad0a9"
  instances_type       = "t4g.nano"
  instances_disk       = "gp3"
  keypair_main_name    = "${var.project_name}-bootstrap-${var.project_environment}-keypair-main"
  ec2_natwg_name  = "${var.project_name}-bootstrap-${var.project_environment}-ec2-natgw"
  ebs_natgw_name       = "${var.project_name}-bootstrap-${var.project_environment}-ebs-natgw"
  ec2_ghrunner_name = "${var.project_name}-bootstrap-${var.project_environment}-ec2-ghrunner"
  ebs_ghrunner_name    = "${var.project_name}-bootstrap-${var.project_environment}-ebs-ghrunner"

  # Instanceprofiles
  instanceprofile_ghrunner = "${var.project_name}-bootstrap-${var.project_environment}-instanceprofile-ghrunner"

  # Security Groups
  sg_test_name     = "${var.project_name}-bootstrap-${var.project_environment}-sg-test"
  sg_natgw_name    = "${var.project_name}-bootstrap-${var.project_environment}-sg-natgw"
  sg_ghrunner_name = "${var.project_name}-bootstrap-${var.project_environment}-sg-runnerid"

  # VPC y Subnets
  vpc_name             = "${var.project_name}-bootstrap-${var.project_environment}-vpc-main"
  azs                  = data.aws_availability_zones.available.names
  azs_len              = length(local.azs)
  public_subnets_cidr  = [for i in range(local.azs_len) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnets_cidr = [for i in range(local.azs_len, local.azs_len * 2) : cidrsubnet(var.vpc_cidr, 8, i)]
  public_subnet_names  = [for az in local.azs : "${var.project_name}-bootstrap-${var.project_environment}-subnet-pub-${az}"]
  private_subnet_names = [for az in local.azs : "${var.project_name}-bootstrap-${var.project_environment}-subnet-priv-${az}"]
  igw_name             = "${var.project_name}-bootstrap-${var.project_environment}-igw-main"

  # Route Tables
  rt_public_name  = "${var.project_name}-bootstrap-${var.project_environment}-rt-public"
  rt_private_name = "${var.project_name}-bootstrap-${var.project_environment}-rt-private"

  # dnsmasq
  dnsmasq_servers = "server=/${var.hostedzone_private}/$ROUTE53_RESOLVER\n"
}