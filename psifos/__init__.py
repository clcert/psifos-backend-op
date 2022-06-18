from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
from flask_marshmallow import Marshmallow
from datetime import timedelta
import configparser
import wtforms_json
from cas import CASClient
import os


# Configuring Environment Variables
config = configparser.ConfigParser()
config.read('.env')


app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1000)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

wtforms_json.init()

# Connection credentials
db_user = config['local']['user']
db_pass = config['local']['password']
db_host = config['local']['host']
db_name = config['local']['database']

# configuring our database uri
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://{0}:{1}@{2}/{3}".format(db_user, db_pass, db_host, db_name)
app.app_context()

db = SQLAlchemy(app, session_options={"autoflush": False})
ma = Marshmallow(app)

from psifos import routes   
from .psifos_auth import routes