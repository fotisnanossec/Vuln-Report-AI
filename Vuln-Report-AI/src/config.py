import tomli
import os
import logging

def load_config(config_path: str = 'config.toml'):
    """
    Loads configuration from a TOML file.
    """
    config_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), config_path)
    if not os.path.exists(config_file):
        logging.error(f"Configuration file not found at {config_file}")
        raise FileNotFoundError(f"Configuration file not found at {config_file}")
        
    try:
        with open(config_file, "rb") as f:
            return tomli.load(f)
    except tomli.TOMLDecodeError as e:
        logging.error(f"Error decoding TOML file: {e}")
        raise
