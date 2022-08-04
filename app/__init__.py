import configparser

# Retrieve enviroment variables from .env file
config = configparser.ConfigParser()
config.read('.env')  