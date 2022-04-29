"""
Routes for Psifos.

24-03-2022
"""
from ctypes import cast
import uuid
import json

from urllib import response

from flask import request, jsonify, make_response, session
from flask.wrappers import Response

from psifos import db
from psifos import app
from psifos.forms import ElectionForm
from psifos.models import Election, Voter, User, Trustee, CastVote
from psifos.schemas import ElectionSchema, VoterSchema, TrusteeSchema, CastVoteSchema
from psifos.psifos_auth.utils import token_required, verify_voter, create_response_cors


# Admin routes


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
                admin_id=current_user.get_id(),
                uuid=str(uuid.uuid1()),
                short_name=data['short_name'],
                name=data['name'],
                description=data['description'],
                election_type=data['election_type'],
                max_weight=data['max_weight'],
                obscure_voter_names=data["obscure_voter_names"],
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
        if election.admin_id == current_user.get_id():
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
        elections = Election.filter_by(schema=election_schema, admin_id=current_user.get_id())
        result = [Election.to_dict(schema=election_schema, obj=e) for e in elections]
        return make_response(jsonify(result), 200)
    except Exception as e:
        print(e)
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
            if Election.get_by_short_name(schema=election_schema, short_name=form.short_name.data) and election.short_name != form.short_name.data:
                return make_response({'message': 'La elección ya existe'}, 400)

            if election.admin_id == current_user.get_id():
                Election.update_or_create(
                    schema=election_schema,
                    admin_id=current_user.get_id(),
                    uuid=election_uuid,
                    short_name=data['short_name'],
                    name=data['name'],
                    description=data['description'],
                    election_type=data['election_type'],
                    max_weight=data['max_weight'],
                    obscure_voter_names=data["obscure_voter_names"],
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
        if election.admin_id == current_user.get_id():
            election.questions = json.dumps(data)
            db.session.commit()
            return make_response(jsonify({"message": "Preguntas creadas con exito!"}), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para crear preguntas en esta elección"}), 401)
    except Exception as e:
        return make_response(jsonify({"message": "Error al editar la elección"}), 400)


@app.route("/get_questions/<election_uuid>", methods=['GET'])
@token_required
def get_questions(current_user, election_uuid: str) -> response:
    """
    Route for get questions
    Require a valid token to access >>> token_required

    """
    try:
        election_schema = ElectionSchema()
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        if not election.questions:
            response = make_response({}, 200)
            return response

        response = make_response(jsonify(json.loads(election.questions)), 200)
        return response

    except Exception as e:
        print(e)
        response = make_response(
            jsonify({"message": "Error al obtener la elección"}), 400)
        return response


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
        if election.admin_id == current_user.get_id():
            voter_schema = VoterSchema()
            cast_vote_schema = CastVoteSchema()
            for voter in file_str:
                print(voter)
                a_voter = Voter.update_or_create(
                    schema=voter_schema,
                    election_id=election.id,
                    uuid=str(uuid.uuid1()),
                    voter_login_id=voter[0],
                    voter_name=voter[1],
                    voter_weight=voter[2],
                )
                CastVote.update_or_create(
                    schema=cast_vote_schema,
                    voter_id=a_voter.id,
                )

        else:
            return make_response(jsonify({"message": "No tiene permisos para enviar votantes a esta elección"}), 401)
        return make_response(jsonify({"message": "Votantes creados con exito!"}), 200)

    except Exception as e:
        raise e
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
        if election.admin_id == current_user.get_id():
            voter_schema = VoterSchema()
            voters = Voter.filter_by(schema=voter_schema, election_id=election.id)
            result = VoterSchema(many=True).dump(voters)
            return make_response(jsonify(result), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para ver esta elección"}), 401)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al obtener los votantes"}), 400)


@app.route("/<election_uuid>/delete_voters", methods=['POST'])
@token_required
def delete_voters(current_user: User, election_uuid) -> Response:
    """
    Route for delete voters
    Require a valid token to access >>> token_required
    """
    try:
        election_schema = ElectionSchema()
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        if election.admin == current_user.get_id():
            Voter.query.filter_by(election=election.id).delete()
            db.session.commit() 
            return make_response(jsonify({"message": "Votantes eliminados con exito!"}), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para eliminar votantes en esta elección"}), 401)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al eliminar los votantes"}), 400)


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
        voters_election = Voter.filter_by(schema=voter_schema, election_id=election.id)
        if election.admin_id == current_user.get_id():
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
        if election.admin_id == current_user.get_id():
            election.openreg = data["openreg"]
            election.save()
            return make_response(jsonify({"message": "Elección reanudada con exito!"}), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para abrir esta elección"}), 401)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al abrir la elección"}), 400)



# Voters routes

@app.route("/<election_uuid>/questions")
def get_questions_voters(election_uuid):
    """
    Route for get questions
    Require a cookie valid in session >>> CAS

    """
    try:

        if verify_voter(session['username'], election_uuid):
            election_schema = ElectionSchema()
            election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
            if not election.questions:
                response = create_response_cors(make_response({}, 200))
                return response

            response = create_response_cors(
                make_response(jsonify(json.loads(election.questions)), 200))
            return response

        else:
            response = create_response_cors(make_response(
                jsonify({"message": "No tiene permisos para acceder a esta elección"}), 401))
            return response

    except Exception as e:
        response = create_response_cors(make_response(
            jsonify({"message": "Error al obtener la elección"}), 400))
        return response


# Trustee Routes
@app.route("/<election_uuid>/create_trustee", methods=['POST'])
@token_required
def create_trustee(current_user: User, election_uuid: str) -> Response:
    """
    Route for create trustee
    Require a valid token to access >>> token_required
    """
    try:
        data = request.get_json()
        election_schema = ElectionSchema()
        election = Election.get_by_uuid(
            schema=election_schema, uuid=election_uuid)
        if election.admin_id == current_user.get_id():
            trustee_schema = TrusteeSchema()
            Trustee.update_or_create(
                schema=trustee_schema,
                election_id=election.id,
                uuid=str(uuid.uuid1()),
                name=data["name"],
                email=data["email"],
            )
            return make_response(jsonify({"message": "Creado con exito!"}), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para crear un trustee"}), 401)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al crear el trustee"}), 400)

@app.route("/<election_uuid>/delete_trustee", methods=['POST'])
@token_required
def delete_trustee(current_user: User, election_uuid: str) -> Response:
    """
    Route for delete trustee
    Require a valid token to access >>> token_required
    """
    try:
        data = request.get_json()
        election_schema = ElectionSchema()
        election = Election.get_by_uuid(
            schema=election_schema, uuid=election_uuid)
        if election.admin_id == current_user.get_id():
            trustee_schema = TrusteeSchema()
            trustee = Trustee.get_by_uuid(
                schema=trustee_schema, uuid=data["uuid"])
            trustee.delete()
            return make_response(jsonify({"message": "Eliminado con exito!"}), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para eliminar un trustee"}), 401)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al eliminar el trustee"}), 400)

@app.route("/<election_uuid>/get_trustees", methods=['GET'])
@token_required
def get_trustees(current_user: User, election_uuid: str) -> Response:
    """
    Route for get trustees
    Require a valid token to access >>> token_required
    """
    try:
        election_schema = ElectionSchema()
        election = Election.get_by_uuid(
            schema=election_schema, uuid=election_uuid)
        if election.admin_id == current_user.get_id():
            trustee_schema = TrusteeSchema()
            trustees = Trustee.filter_by(
                schema=trustee_schema, election_id=election.id)
            result = [Trustee.to_dict(schema=trustee_schema, obj=e) for e in trustees]
            response = make_response(jsonify(result), 200)
            return response
        else:
            return make_response(jsonify({"message": "No tiene permisos para obtener los trustees"}), 401)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al obtener los trustees"}), 400)