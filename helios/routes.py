from flask import request, jsonify, make_response
from helios import app
from helios.models import Election, Voter
from helios import db
from helios.schemas import ElectionDetailSchema, VoterSchema
from helios.helios_auth.utils import token_required
from helios.forms import ElectionForm

import uuid
import json


@app.route("/create_election", methods=['POST'])
@token_required
def create_election(current_user):

    try:
        data = request.get_json()
        form = ElectionForm.from_json(data)

        if form.validate():
            if Election.get_by_short_name(form.short_name.data):
                return make_response({'message': 'La elección ya existe'}, 400)

            Election.update_or_create(
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
    try:
        election = Election.query.filter_by(uuid=election_uuid).first()
        if election.admin == current_user.get_id():
            result = ElectionDetailSchema().dump(election)
            return jsonify(result)
        else:
            return make_response(jsonify({"message": "No tiene permisos para ver esta elección"}), 401)
    except Exception as e:
        print(e)
        return jsonify({"message": "Error al obtener la elección"})


@app.route("/get_elections", methods=['GET'])
@token_required
def get_elections(current_user):
    try:
        elections = Election.query.filter_by(admin=current_user.get_id()).all()
        result = ElectionDetailSchema(many=True).dump(elections)
        return make_response(jsonify(result), 200)
    except Exception as e:
        return make_response(jsonify({"message": "Error al obtener la elección"}), 400)


@app.route("/edit_election/<election_uuid>", methods=['POST'])
@token_required
def edit_election(current_user, election_uuid):
    try:

        data = request.get_json()
        form = ElectionForm.from_json(data)

        if form.validate():
            election = Election.query.filter_by(uuid=election_uuid).first()
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
    try:
        data = request.get_json()
        election = Election.query.filter_by(uuid=election_uuid).first()
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
def get_questions(current_user, election_uuid):
    try:
        election = Election.query.filter_by(uuid=election_uuid).first()
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
def send_voters(current_user, election_uuid):
    try:
        file_input = request.files["file"]
        file_str = file_input.read().decode("utf-8")
        file_str = file_str.split("\n")
        file_str = [x.split(",") for x in file_str]
        election = Election.query.filter_by(uuid=election_uuid).first()
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
def get_voters(current_user, election_uuid):
    try:
        election = Election.query.filter_by(uuid=election_uuid).first()
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
def resume(current_user, election_uuid):
    try:

        election = Election.query.filter_by(uuid=election_uuid).first()
        voters_election = Voter.query.filter_by(election=election.id).all()
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
def openreg(current_user, election_uuid):
    try:
        data = request.get_json()
        election = Election.query.filter_by(uuid=election_uuid).first()
        if election.admin == current_user.get_id():
            election.openreg = data["openreg"]
            db.session.commit()
            return make_response(jsonify({"message": "Elección reanudada con exito!"}), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para abrir esta elección"}), 401)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al abrir la elección"}), 400)
