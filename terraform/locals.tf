locals {
  azs = data.aws_availability_zones.available.names
  keypair_name = "${var.project_name}-bootstrap-${var.project_environment}-keypair-main"
}
