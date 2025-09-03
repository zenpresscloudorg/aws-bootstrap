import json
import sys

REQUIRED_VARS = [
    "project_name",
    "project_environment",
    "vpc_cidr",
    "vpc_ipv6",
    "vpc_subnet_nat",
    "hostedzones_public",
    "hostedzones_private",
    "vpc_subnet_nat_tskey",
    "github_account",
    "github_repo"
]

ARRAY_VARS = [
    "hostedzones_public",
    "hostedzones_private"
]

with open("vars.json") as f:
    data = json.load(f)

missing = [var for var in REQUIRED_VARS if var not in data]
wrong_type = [var for var in ARRAY_VARS if var in data and not isinstance(data[var], list)]

if missing or wrong_type:
    if missing:
        print(f"Missing required variables in vars.json: {', '.join(missing)}", file=sys.stderr)
    if wrong_type:
        print(f"These variables must be arrays (even if empty): {', '.join(wrong_type)}", file=sys.stderr)
    sys.exit(1)

for var in REQUIRED_VARS:
    print(f"{var}: {data[var]}")
