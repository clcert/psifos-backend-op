from flask import request, jsonify, make_response
from helios import app
from werkzeug.security import check_password_hash
from helios.helios_auth.models import User

import datetime
import jwt


@app.route('/login', methods=['GET', 'POST'])
def login_user():

    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response({'message': 'Ocurrio un error, intente nuevamente'}, 401)

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response({'message': 'Usuario o contraseñas incorrectos'}, 401)

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id},
                           app.config['SECRET_KEY'])
        return jsonify({'token': token})

    else:
        return make_response({'message': 'Usuario o contraseñas incorrectos'}, 401)
