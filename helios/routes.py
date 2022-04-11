
"""
Routes for Psifos.

24-03-2022
"""

from helios import db
from helios import app
from helios.forms import ElectionForm
from helios.models import Election, Voter, User
from helios.schemas import ElectionSchema, VoterSchema
from helios.helios_auth.utils import token_required

from flask import request, jsonify, make_response
from flask.wrappers import Response

import uuid
import json


@app.route("/create_election", methods=['POST'])
@token_required
def create_election(current_user: User) -> Response:
    """
    Route for create a new election
    Require a valid token to access >>> token_required

    """

    try:
        data = request.get_json()
        form = ElectionForm.from_json(data)

        if form.validate():
            election_schema = ElectionSchema()
            if Election.get_by_short_name(schema=election_schema, short_name=form.short_name.data):
                return make_response({'message': 'La elección ya existe'}, 400)

            Election.update_or_create(
                schema=election_schema,
                admin=current_user.get_id(),
                uuid=str(uuid.uuid1()),
                short_name=data['short_name'],
                name=data['name'],
                description=data['description'],
                election_type=data['election_type'],
                help_email=data["help_email"],
                max_weight=data['max_weight'],
                voting_started_at=data["voting_started_at"],
                voting_ends_at=data["voting_ends_at"],
                use_voter_aliases=data["use_voter_aliases"],
                randomize_answer_order=data["randomize_answer_order"],
                private_p=data["private_p"],
                normalization=data["normalization"],
                openreg=False)

            return make_response(jsonify({"message": "Elección creada con exito!"}), 200)

        else:
            return make_response(jsonify({"message": form.errors}), 400)

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al crear la elección"}), 400)


@app.route("/get_election/<election_uuid>", methods=['GET'])
@token_required
def get_election(current_user, election_uuid):
    """
    Route for get a election by uuid
    Require a valid token to access >>> token_required
    """
    try:
        election_schema = ElectionSchema()
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        if election.admin == current_user.get_id():
            result = ElectionSchema().dump(election)
            return jsonify(result)
        else:
            return make_response(jsonify({"message": "No tiene permisos para ver esta elección"}), 401)
    except Exception as e:
        print(e)
        return jsonify({"message": "Error al obtener la elección"})


@app.route("/get_elections", methods=['GET'])
@token_required
def get_elections(current_user):
    """
    Route for get all elections
    Require a valid token to access >>> token_required

    """

    try:
        election_schema = ElectionSchema()
        elections = Election.filter_by(schema=election_schema, admin=current_user.get_id())
        result = [Election.serialize(schema=election_schema, obj=e) for e in elections]
        return make_response(jsonify(result), 200)
    except Exception as e:
        return make_response(jsonify({"message": "Error al obtener la elección"}), 400)


@app.route("/edit_election/<election_uuid>", methods=['POST'])
@token_required
def edit_election(current_user, election_uuid):
    """
    Route for edit a election
    Require a valid token to access >>> token_required   
    """
    try:
        data = request.get_json()
        form = ElectionForm.from_json(data)
        election_schema = ElectionSchema() 

        if form.validate():
            election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
            if Election.get_by_short_name(form.short_name.data) and election.short_name != form.short_name.data:
                return make_response({'message': 'La elección ya existe'}, 400)

            if election.admin == current_user.get_id():
                Election.update_or_create(
                    admin=current_user.get_id(),
                    uuid=election_uuid,
                    short_name=data['short_name'],
                    name=data['name'],
                    description=data['description'],
                    election_type=data['election_type'],
                    help_email=data["help_email"],
                    max_weight=data['max_weight'],
                    voting_started_at=data["voting_started_at"],
                    voting_ends_at=data["voting_ends_at"],
                    use_voter_aliases=data["use_voter_aliases"],
                    randomize_answer_order=data["randomize_answer_order"],
                    private_p=data["private_p"],
                    normalization=data["normalization"])
                return make_response(jsonify({"message": "Elección editada con exito!"}), 200)
            else:
                return make_response(jsonify({"message": "No tiene permisos para editar esta elección"}), 401)

        else:
            return make_response(jsonify({"message": form.errors}), 400)

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al editar la elección"}), 400)


@app.route("/create_questions/<election_uuid>", methods=['POST'])
@token_required
def create_questions(current_user, election_uuid):
    """
    Route for create questions
    Require a valid token to access >>> token_required
    """

    try:
        data = request.get_json()
        election_schema = ElectionSchema()
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        if election.admin == current_user.get_id():
            election.questions = json.dumps(data)
            db.session.commit()
            return make_response(jsonify({"message": "Preguntas creadas con exito!"}), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para crear preguntas en esta elección"}), 401)
    except Exception as e:
        return make_response(jsonify({"message": "Error al editar la elección"}), 400)


@app.route("/get_questions/<election_uuid>", methods=['GET'])
@token_required
def get_questions(current_user: User, election_uuid: str) -> Response:
    """
    Route for get questions
    Require a valid token to access >>> token_required

    """
    try:
        election_schema = ElectionSchema()
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        if not election.questions:
            return make_response({}, 200)

        if election.admin == current_user.get_id():

            return make_response(jsonify(json.loads(election.questions)), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para ver esta elección"}), 401)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al obtener la elección"}), 400)


@app.route("/<election_uuid>/send_voters", methods=['POST'])
@token_required
def send_voters(current_user, election_uuid) -> Response:
    """
    Route for send voters   
    Require a valid token to access >>> token_required  
    """
    try:
        file_input = request.files["file"]
        file_str = file_input.read().decode("utf-8")
        file_str = file_str.split("\n")
        file_str = [x.split(",") for x in file_str]

        election_schema = ElectionSchema()
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        if election.admin == current_user.get_id():
            for voter in file_str:
                Voter.update_or_create(
                    election=election.id,
                    uuid=str(uuid.uuid1()),
                    voter_name=voter[0],
                    voter_email=voter[1],
                    alias=voter[2],
                    voter_weight=voter[3])

        else:
            return make_response(jsonify({"message": "No tiene permisos para enviar votantes a esta elección"}), 401)
        return make_response(jsonify({"message": "Votantes creados con exito!"}), 200)

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al enviar los votantes"}), 400)


@app.route("/<election_uuid>/get_voters", methods=['GET'])
@token_required
def get_voters(current_user: User, election_uuid) -> Response:
    """
    Route for get voters
    Require a valid token to access >>> token_required
    """

    try:
        election_schema = ElectionSchema()
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        if election.admin == current_user.get_id():
            voters = Voter.query.filter_by(election=election.id).all()
            result = VoterSchema(many=True).dump(voters)
            return make_response(jsonify(result), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para ver esta elección"}), 401)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al obtener los votantes"}), 400)


@app.route("/<election_uuid>/resume", methods=['GET'])
@token_required
def resume(current_user: User, election_uuid: str) -> Response:
    """
    Route for get a resume election
    Require a valid token to access >>> token_required

    """
    try:
        election_schema = ElectionSchema()
        voter_schema = VoterSchema()
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        voters_election = Voter.filter_by(schema=voter_schema, election=election.id)
        if election.admin == current_user.get_id():
            election.resume()
            return make_response(jsonify({"election": "Elección reanudada con exito!"}), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para reanudar esta elección"}), 401)

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al reanudar la elección"}), 400)


@app.route("/<election_uuid>/openreg", methods=['POST'])
@token_required
def openreg(current_user: User, election_uuid: str) -> Response:
    """

    Route for open election
    Require a valid token to access >>> token_required
    """
    try:
        data = request.get_json()
        election_schema = ElectionSchema()
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        if election.admin == current_user.get_id():
            election.openreg = data["openreg"]
            db.session.commit()
            return make_response(jsonify({"message": "Elección reanudada con exito!"}), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para abrir esta elección"}), 401)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al abrir la elección"}), 400)
