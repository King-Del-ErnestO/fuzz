import yaml

def parse_yaml(data: str):
    # Use safe loader
    return yaml.safe_load(data)
