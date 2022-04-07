from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
from flask_marshmallow import Marshmallow
from datetime import timedelta
import configparser
import wtforms_json
from cas import CASClient


# Configuring Environment Variables
config = configparser.ConfigParser()
config.read('.env')


app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1000)

CORS(app)

cas_client = CASClient(
    version=3,
    service_url=config['URL']['back']+ '/vote/',
    server_url='https://cas.labs.clcert.cl/'
)

wtforms_json.init()

# Schemas

# Connection credentials
db_user = config['local']['user']
db_pass = config['local']['password']
db_host = config['local']['host']
db_name = config['local']['database']

# configuring our database uri
app.config["SQLALCHEMY_DATABASE_URI"] = "postgres://{0}:{1}@{2}/{3}".format(db_user, db_pass, db_host, db_name)
app.app_context()

db = SQLAlchemy(app)
ma = Marshmallow(app)

from helios import routes
from .helios_auth import routes