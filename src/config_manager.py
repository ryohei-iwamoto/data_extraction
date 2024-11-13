import configparser

class ConfigManager:
    def __init__(self, filename):
        self.config = configparser.ConfigParser()
        self.filename = filename
        self.load_config()

    def load_config(self):
        self.config.read(self.filename)

    def save_config(self, section, key, value):
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
        with open(self.filename, 'w') as f:
            self.config.write(f)
