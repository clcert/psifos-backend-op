from flask import request, jsonify, make_response
from helios import app
from helios.models import Election
from helios import db
from helios.shemas import ElectionDetailSchema
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

            election = Election(admin=current_user.get_id(), uuid=str(uuid.uuid1()), short_name=data['short_name'], name=data['name'],
                                description=data['description'], election_type=data['election_type'],
                                help_email=data["help_email"], max_weight=data['max_weight'],
                                voting_started_at=data["voting_started_at"], voting_ends_at=data["voting_ends_at"],
                                use_voter_aliases=data["use_voter_aliases"], randomize_answer_order=data["randomize_answer_order"],
                                private_p=data["private_p"], normalization=data["normalization"],  openreg=False)
            db.session.add(election)
            db.session.commit()
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
            if election.admin == current_user.get_id():
                election.short_name = data['short_name']
                election.name = data['name']
                election.description = data['description']
                election.election_type = data['election_type']
                election.help_email = data['help_email']
                election.max_weight = data['max_weight']
                election.voting_started_at = data["voting_started_at"]
                election.voting_ends_at = data["voting_ends_at"]
                election.use_voter_aliases = data["use_voter_aliases"]
                election.randomize_answer_order = data["randomize_answer_order"]
                election.private_p = data["private_p"]
                election.normalization = data["normalization"]
                db.session.commit()
                return make_response(jsonify({"message": "Elección editada con exito!"}), 200)
            else:
                return make_response(jsonify({"message": "No tiene permisos para editar esta elección"}), 401)

        else:
            return make_response(jsonify({"message": form.errors}), 400)

    except Exception as e:
        return make_response(jsonify({"message": "Error al editar la elección"}), 400)


@app.route("/create_questions/<election_uuid>", methods=['POST'])
@token_required
def create_questions(current_user, election_uuid):
    try:
        data = request.get_json()
        print(json.dumps(data))
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
        if election.admin == current_user.get_id():
            return make_response(jsonify(json.loads(election.questions)), 200)
        else:
            return make_response(jsonify({"message": "No tiene permisos para ver esta elección"}), 401)
    except Exception as e:
        return make_response(jsonify({"message": "Error al obtener la elección"}), 400)
