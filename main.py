from validator import validate_vars

def main():
    vars_data = validate_vars()
    # Aquí puedes seguir usando vars_data como quieras
    print("Variables validadas correctamente:")
    for k, v in vars_data.items():
        print(f"{k}: {v}")