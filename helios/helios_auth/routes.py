from flask import request, jsonify, make_response, redirect, session
from helios import app
from werkzeug.security import check_password_hash
from helios.helios_auth.models import User
from helios import cas_client
from helios import config

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



@app.route('/CASLogin', methods=['GET', 'POST'])
def CASLogin():

    if 'username' in session:
        # Already logged in
        return redirect(config['URL']['front'] + "/cabina/2", code=302)

    ticket = request.args.get('ticket')
    print("ticket", ticket)
    if not ticket:
        # No ticket, the request come from end user, send to CAS login
        cas_login_url = cas_client.get_login_url()
        
        return redirect(cas_login_url)

    user, attributes, pgtiou = cas_client.verify_ticket(ticket)
    if not user:
        return make_response({'message': 'ERROR'}, 401)
    else:  # Login successfully, redirect according `next` query parameter.
        session['username'] = user
        return redirect(config['URL']['front'] + "/cabina/2", code=302)



