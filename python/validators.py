import ipaddress
import os
import json

def load_and_validate_vars_json(file):
    """
    Loads and validates vars.json from the same directory as the script.
    Returns the validated dictionary.
    Raises FileNotFoundError or ValueError if something is wrong.
    """
    # Load file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    vars_path = os.path.join(script_dir, file)
    if not os.path.isfile(vars_path):
        raise FileNotFoundError(f"vars.json file not found at: {vars_path}")

    with open(vars_path, "r") as f:
        vars_json = json.load(f)

    # Validate fields
    required_fields = {
        "project_name": str,
        "project_environment": str,
        "vpc_cidr": str,
        "vpc_ipv6_enable": bool,
        "vpc_subnet_private_enable": bool,
        "vpc_subnet_private_tskey": str,
        "hostedzones_public": list,
        "hostedzones_private": list,
        "github_org": str,
        "github_runner_token": str,
    }

    missing = []
    wrong_type = []

    for key, typ in required_fields.items():
        if key not in vars_json:
            missing.append(key)
        elif not isinstance(vars_json[key], typ):
            wrong_type.append(f"{key} (expected {typ.__name__}, got {type(vars_json[key]).__name__})")
    
    if missing:
        raise ValueError(f"Missing required keys in vars.json: {', '.join(missing)}")
    if wrong_type:
        raise ValueError(f"Type error(s) in vars.json: {', '.join(wrong_type)}")
    
    # Check all elements in hostedzones are str
    for list_key in ("hostedzones_public", "hostedzones_private"):
        if any(not isinstance(item, str) for item in vars_json[list_key]):
            raise ValueError(f"All elements in {list_key} must be strings")
    
    # Check vpc_cidr is valid IPv4 CIDR
    try:
        net = ipaddress.IPv4Network(vars_json["vpc_cidr"])
    except Exception as e:
        raise ValueError(f"vpc_cidr is not a valid IPv4 CIDR: {vars_json['vpc_cidr']}. Error: {e}")

    return vars_json
