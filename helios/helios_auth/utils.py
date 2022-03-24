from werkzeug.security import generate_password_hash
from functools import wraps
from flask import request, jsonify
from helios import app, db
from helios.helios_auth.models import User
import jwt
import uuid


def token_required(f):
    """
    Decorator to check if the user is logged in

    """

    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=['HS256'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except Exception as e:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args,  **kwargs)
    return decorator


def create_user(username, password):
    """
    Create a new user
    :param username: username of the user
    :param password: password of the user


    """

    hashed_password = generate_password_hash(password, method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), user_type="password",
                    user_id="admin", name=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return "Usuario creado"
