locals {
  azs = data.aws_availability_zones.available.names
  azs_len = length(local.azs)
  keypair_name = "${var.project_name}-bootstrap-${var.project_environment}-keypair-main"
  public_subnets_cidr = [for i in range(local.azs_len) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnets_cidr = [for i in range(local.azs_len, local.azs_len * 2) : cidrsubnet(var.vpc_cidr, 8, i)]
  public_subnet_names = [for az in local.azs : "${var.project_name}-bootstrap-${var.project_environment}-subnet-pub-${az}"]
  private_subnet_names = [for az in local.azs : "${var.project_name}-bootstrap-${var.project_environment}-subnet-priv-${az}"]
  sg_test_name    = "${var.project_name}-bootstrap-${var.project_environment}-sg-test"
  sg_natgw_name   = "${var.project_name}-bootstrap-${var.project_environment}-sg-natgw"
  sg_ghrunner_name = "${var.project_name}-bootstrap-${var.project_environment}-sg-runnerid"  
  igw_name = "${var.project_name}-bootstrap-${var.project_environment}-igw-main"
  natgw_instance_name = "${var.project_name}-bootstrap-${var.project_environment}-ec2-natgw"
  natgw_ebs_name      = "${var.project_name}-bootstrap-${var.project_environment}-ebs-natgw"
  dnsmasq_servers     = join("", [for domain in var.hostedzones_private : "server=/${domain}/$ROUTE53_RESOLVER\n"])
  instances_ami   = "ami-0cd0767d8ed6ad0a9"
  instances_type  = "t4g.nano"
}