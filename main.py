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

# Search for key pair by both Product and Usage tags
keypair = find_aws_key_pair_by_tags({"product": VAR_PRODUCT, "Usage": "main"}, vars_data["account_region"])
if keypair:
    print(keypair["key_name"])
else:
    print(generate_key_pair())