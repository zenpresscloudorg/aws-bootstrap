# Imports

import os
from utils import *

# Vars
try:
    VAR_PRODUCT = "bootstrap"
    vars_data = load_vars_json()
except Exception as e:
    print(f"Error loading vars.json: {e}")
    exit(1)

# SSH Key

keypairs = find_aws_key_pairs_by_tag("product", VAR_PRODUCT, vars_data["account_region"])
if keypairs:
    # If exists, print the name of the first key pair
    print(keypairs[0]["key_name"])
else:
    # If not exists, generate a new key pair and print the JSON
    print(generate_key_pair())