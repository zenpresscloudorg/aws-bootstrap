
# Hostedzone

resource "aws_route53_zone" "public" {
  name = var.hostedzone_public
}

