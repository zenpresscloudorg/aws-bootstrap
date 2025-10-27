# Imports

import os
from utils import *

# Vars
try:
    vars_data = load_vars_json()
    VAR_ACCOUNT = {
        "account": vars_data["account_name"],
        "environment": vars_data["account_environment"],
        "region": vars_data["account_region"]
    }
    VAR_PRODUCT = "bootstrap"
except Exception as e:
    print(f"Error loading vars.json: {e}")
    exit(1)

# SSH Key



key_name = find_aws_key_pair_by_tags(**VAR_ACCOUNT,product=VAR_PRODUCT,usage="main"
if key_name:
    print(key_name)
else:
    key_name = create_aws_key_pair(**VAR_ACCOUNT,product=VAR_PRODUCT,usage="main")
    print(key_name)