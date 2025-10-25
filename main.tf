
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