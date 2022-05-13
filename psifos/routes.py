"""
Routes for Psifos.

24-03-2022
"""
from ctypes import cast
import uuid
import json
import base64
import os


from urllib import response

from flask import request, jsonify, make_response, session
from flask.wrappers import Response

from psifos import db
from psifos import app
from psifos.forms import ElectionForm
from psifos.models import Election, Voter, User, Trustee, CastVote
from psifos.psifos_model import PsifosModel
from psifos.schemas import ElectionSchema, VoterSchema, TrusteeSchema, CastVoteSchema
from psifos.models import CastVote, Election, Voter, User
from psifos.psifos_object.questions import Questions
from psifos.psifos_auth.utils import (
    admin_election,
    cas_requires,
    token_required,
    verify_trustee,
    verify_voter,
    create_response_cors,
)

from sqlalchemy import func

from psifos.serialization import SerializableList

# Schemas Instances
election_schema = ElectionSchema()
voter_schema = VoterSchema()
trustee_schema = TrusteeSchema()
cast_vote_schema = CastVoteSchema()

# Admin routes


@app.route("/create_election", methods=["POST"])
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
            if Election.get_by_short_name(
                schema=election_schema, short_name=form.short_name.data
            ):
                return make_response({"message": "La elección ya existe"}, 400)

            uuid_election = str(uuid.uuid4())
            election = Election.update_or_create(
                schema=election_schema,
                admin_id=current_user.get_id(),
                uuid=uuid_election,
                short_name=data["short_name"],
                name=data["name"],
                description=data["description"],
                election_type=data["election_type"],
                max_weight=data["max_weight"],
                obscure_voter_names=data["obscure_voter_names"],
                randomize_answer_order=data["randomize_answer_order"],
                private_p=data["private_p"],
                normalization=data["normalization"],
                openreg=False,
            )
            election.save()
            return make_response(
                jsonify(
                    {"message": "Elección creada con exito!", "uuid": uuid_election}
                ),
                200,
            )

        else:
            return make_response(jsonify({"message": form.errors}), 400)

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al crear la elección"}), 400)


@app.route("/get_election/<election_uuid>", methods=["GET"])
@token_required
@admin_election
def get_election(
    election: Election, current_user: User, election_uuid: str
) -> Response:
    """
    Route for get a election by uuid
    Require a valid token to access >>> token_required
    """
    try:

        result = Election.to_dict(schema=election_schema, obj=election)
        response = make_response(result, 200)
        return response

    except Exception as e:
        print(e)
        response = create_response_cors(
            make_response(jsonify({"message": "Error al obtener la elección"}), 400)
        )
        return response


@app.route("/get_elections", methods=["GET"])
@token_required
def get_elections(current_user: User):
    """
    Route for get all elections
    Require a valid token to access >>> token_required

    """

    try:
        elections = Election.filter_by(
            schema=election_schema, admin_id=current_user.get_id()
        )
        result = [Election.to_dict(schema=election_schema, obj=e) for e in elections]
        return make_response(jsonify(result), 200)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al obtener la elección"}), 400)


@app.route("/edit_election/<election_uuid>", methods=["POST"])
@token_required
@admin_election
def edit_election(
    election: Election, current_user: User, election_uuid: str
) -> Response:
    """
    Route for edit a election
    Require a valid token to access >>> token_required
    """
    try:
        data = request.get_json()
        form = ElectionForm.from_json(data)

        if form.validate():
            if (
                Election.get_by_short_name(
                    schema=election_schema, short_name=form.short_name.data
                )
                and election.short_name != form.short_name.data
            ):
                return make_response({"message": "La elección ya existe"}, 400)

            election = Election.update_or_create(
                schema=election_schema,
                admin_id=current_user.get_id(),
                uuid=election_uuid,
                short_name=data["short_name"],
                name=data["name"],
                description=data["description"],
                election_type=data["election_type"],
                max_weight=data["max_weight"],
                obscure_voter_names=data["obscure_voter_names"],
                randomize_answer_order=data["randomize_answer_order"],
                private_p=data["private_p"],
                normalization=data["normalization"],
            )
            election.save()
            return make_response(
                jsonify(
                    {
                        "message": "Elección editada con exito!",
                        "uuid": election_uuid,
                    }
                ),
                200,
            )

        else:
            return make_response(jsonify({"message": form.errors}), 400)

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al editar la elección"}), 400)


@app.route("/create_questions/<election_uuid>", methods=["POST"])
@token_required
@admin_election
def create_questions(
    election: Election, current_user: User, election_uuid: str
) -> Response:
    """
    Route for create questions
    Require a valid token to access >>> token_required
    """

    try:
        data = request.get_json()
        questions = Questions(*data["question"])
        election.questions = questions
        election.save()
        return make_response(jsonify({"message": "Preguntas creadas con exito!"}), 200)

    except Exception as e:
        raise e
        return make_response(jsonify({"message": "Error al editar la elección"}), 400)


@app.route("/get_questions/<election_uuid>", methods=["GET"])
@token_required
@admin_election
def get_questions(
    election: Election, current_user: User, election_uuid: str
) -> response:
    """
    Route for get questions
    Require a valid token to access >>> token_required

    """
    try:
        election = Election.get_by_uuid(
            schema=election_schema, uuid=election_uuid, deserialize=True
        )
        json_questions = Questions.serialize(election.questions)
        if not election.questions:
            response = make_response({}, 200)
            return response
        json_questions = SerializableList.serialize(election.questions)
        response = make_response(json_questions, 200)
        return response

    except Exception as e:
        print(e)
        response = make_response(
            jsonify({"message": "Error al obtener la elección"}), 400
        )
        return response


@app.route("/<election_uuid>/send_voters", methods=["POST"])
@token_required
@admin_election
def send_voters(election: Election, current_user: User, election_uuid: str) -> Response:
    """
    Route for send voters
    Require a valid token to access >>> token_required
    """
    try:
        file_input = request.files["file"]
        file_str = file_input.read().decode("utf-8")
        strip_lines = [line.strip() for line in file_str.split("\n")]
        data = [x.split(",") for x in strip_lines]

        for voter in data:
            a_voter = Voter.update_or_create(
                schema=voter_schema,
                election_id=election.id,
                uuid=str(uuid.uuid1()),
                voter_login_id=voter[0],
                voter_name=voter[1],
                voter_weight=voter[2],
            )
            a_voter.save()
            a_cast_vote = CastVote.update_or_create(
                schema=cast_vote_schema,
                voter_id=a_voter.id,
            )
            a_cast_vote.save()

        return make_response(jsonify({"message": "Votantes creados con exito!"}), 200)

    except Exception as e:
        raise e
        return make_response(jsonify({"message": "Error al enviar los votantes"}), 400)


@app.route("/<election_uuid>/get_voters", methods=["GET"])
@token_required
@admin_election
def get_voters(election: Election, current_user: User, election_uuid: str) -> Response:
    """
    Route for get voters
    Require a valid token to access >>> token_required
    """

    try:
        voters = Voter.filter_by(schema=voter_schema, election_id=election.id)
        result = [Voter.to_dict(schema=voter_schema, obj=e) for e in voters]
        return make_response(jsonify(result), 200)

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al obtener los votantes"}), 400)


@app.route("/<election_uuid>/delete_voters", methods=["POST"])
@token_required
@admin_election
def delete_voters(
    election: Election, current_user: User, election_uuid: str
) -> Response:
    """
    Route for delete voters
    Require a valid token to access >>> token_required
    """
    try:

        voters = Voter.filter_by(schema=voter_schema, election_id=election.id)
        list(map(lambda x: x.delete(), voters))
        return make_response(
            jsonify({"message": "Votantes eliminados con exito!"}), 200
        )

    except Exception as e:
        print(e)
        return make_response(
            jsonify({"message": "Error al eliminar los votantes"}), 400
        )


@app.route("/<election_uuid>/resume", methods=["GET"])
@token_required
def resume(current_user: User, election_uuid: str) -> Response:
    """
    Route for get a resume election
    Require a valid token to access >>> token_required
    """
    try:
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        voters_election = Voter.filter_by(schema=voter_schema, election_id=election.id)
        if election.admin_id == current_user.get_id():
            count_weight = (
                Voter.query.with_entities(
                    Voter.voter_weight, func.count(Voter.voter_weight)
                )
                .group_by(Voter.voter_weight)
                .all()
            )
            total_voters = Voter.query.filter_by(election_id=election.id).count()
            return make_response(
                jsonify({"weights": count_weight, "total_voters": total_voters}), 200
            )
        else:
            return make_response(
                jsonify({"message": "No tiene permisos ver esta elección"}), 401
            )

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al reanudar la elección"}), 400)


@app.route("/<election_uuid>/openreg", methods=["POST"])
@token_required
@admin_election
def openreg(election: Election, current_user: User, election_uuid: str) -> Response:
    """
    Route for open election
    Require a valid token to access >>> token_required
    """
    try:
        data = request.get_json()
        election.openreg = data["openreg"]
        election.save()
        return make_response(jsonify({"message": "Elección reanudada con exito!"}), 200)

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al abrir la elección"}), 400)


# Voters routes


@app.route("/<election_uuid>/questions")
@cas_requires
def get_questions_voters(election_uuid):
    """
    Route for get questions
    Require a cookie valid in session >>> CAS

    """
    try:

        if verify_voter(session["username"], election_uuid):
            election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
            result = Election.to_dict(schema=election_schema, obj=election)
            response = create_response_cors(make_response(result, 200))
            return response

        else:
            response = create_response_cors(
                make_response(
                    jsonify(
                        {"message": "No tiene permisos para acceder a esta elección"}
                    ),
                    401,
                )
            )
            return response

    except Exception as e:
        response = create_response_cors(
            make_response(jsonify({"message": "Error al obtener la elección"}), 400)
        )
        return response


# Trustee Routes
@app.route("/<election_uuid>/create_trustee", methods=["POST"])
@token_required
def create_trustee(current_user: User, election_uuid: str) -> Response:
    """
    Route for create trustee
    Require a valid token to access >>> token_required
    """
    try:
        data = request.get_json()
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        if election.admin_id == current_user.get_id():
            trustee = Trustee.update_or_create(
                schema=trustee_schema,
                election_id=election.id,
                uuid=str(uuid.uuid1()),
                name=data["name"],
                trustee_login_id=data["trustee_login_id"],
                email=data["email"],
            )
            trustee.save()
            return make_response(jsonify({"message": "Creado con exito!"}), 200)
        else:
            return make_response(
                jsonify({"message": "No tiene permisos para crear un trustee"}), 401
            )
    except Exception as e:
        raise e
        return make_response(jsonify({"message": "Error al crear el trustee"}), 400)


@app.route("/<election_uuid>/delete_trustee", methods=["POST"])
@token_required
def delete_trustee(current_user: User, election_uuid: str) -> Response:
    """
    Route for delete trustee
    Require a valid token to access >>> token_required
    """
    try:
        data = request.get_json()
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        if election.admin_id == current_user.get_id():
            trustee = Trustee.get_by_uuid(schema=trustee_schema, uuid=data["uuid"])
            trustee.delete()
            return make_response(jsonify({"message": "Eliminado con exito!"}), 200)
        else:
            return make_response(
                jsonify({"message": "No tiene permisos para eliminar un trustee"}), 401
            )
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al eliminar el trustee"}), 400)


@app.route("/<election_uuid>/get_trustees", methods=["GET"])
@token_required
def get_trustees(current_user: User, election_uuid: str) -> Response:
    """
    Route for get trustees
    Require a valid token to access >>> token_required
    """
    try:
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        if election.admin_id == current_user.get_id():
            trustees = Trustee.filter_by(schema=trustee_schema, election_id=election.id)
            result = [Trustee.to_dict(schema=trustee_schema, obj=e) for e in trustees]
            response = make_response(jsonify(result), 200)
            return response
        else:
            return make_response(
                jsonify({"message": "No tiene permisos para obtener los trustees"}), 401
            )
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al obtener los trustees"}), 400)


@app.route("/<trustee_uuid>/get_trustee", methods=["GET"])
def get_trustee(trustee_uuid):
    """
    Route for get trustee
    """
    try:
        trustee = Trustee.get_by_uuid(schema=trustee_schema, uuid=trustee_uuid)
        response = make_response(
            jsonify(Trustee.to_dict(schema=trustee_schema, obj=trustee)), 200
        )
        return response
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al obtener el trustee"}), 400)


@app.route("/<election_uuid>/trustee/<trustee_uuid>/home", methods=["GET"])
@cas_requires
def get_trustee_home(election_uuid, trustee_uuid):
    """
    Route for get trustee home
    Require a cookie valid in session >>> CAS
    """
    try:

        if verify_trustee(session["username"], election_uuid):
            election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
            trustee = Trustee.filter_by(
                schema=trustee_schema, uuid=trustee_uuid, election_id=election.id
            )

            if not trustee:
                response = create_response_cors(
                    make_response(
                        jsonify(
                            {
                                "message": "No tiene permisos para acceder a esta elección"
                            }
                        ),
                        401,
                    )
                )
                return response

            response = create_response_cors(
                make_response(
                    jsonify(Trustee.to_dict(schema=trustee_schema, obj=trustee)), 200
                )
            )
            return response

        else:
            response = create_response_cors(
                make_response(
                    jsonify(
                        {"message": "No tiene permisos para acceder a esta elección"}
                    ),
                    401,
                )
            )
            return response

    except Exception as e:
        response = create_response_cors(
            make_response(jsonify({"message": "Error al obtener la elección"}), 400)
        )
        return response


@app.route("/<election_uuid>/get_randomness", methods=["GET"])
def get_randomness(election_uuid: str) -> Response:
    """
    Get some randomness to sprinkle into the sjcl entropy pool

    """
    response = make_response(
        jsonify({"randomness": base64.b64encode(os.urandom(32)).decode("utf-8")}), 200
    )

    return response


# Routes for keygenerator trustee


@app.route("/<election_uuid>/trustee/<trustee_uuid>/get_step", methods=["GET"])
def get_step(election_uuid: str, trustee_uuid: str) -> Response:
    """
    Get the step of the trustee
    """
    pass


@app.route("/<election_uuid>/trustee/<trustee_uuid>/upload_pk", methods=["POST"])
def trustee_upload_pk(election_uuid: str, trustee_uuid: str) -> Response:
    """
    Upload public key of trustee
    """
    try:
        data = request.get_json()
        with open("trustee_upload_pk.json", "w+") as f:
            f.write(data)

    except Exception as e:
        print(e)
        return make_response(
            jsonify({"message": "Error al obtener el certificado del trustee"}), 400
        )


@app.route("/<election_uuid>/trustee/<trustee_uuid>/step1", methods=["GET", "POST"])
def truustee_step_1(election_uuid: str, trustee_uuid: str) -> Response:
    """
    Step 1 of the keygenerator trustee
    """

    if request.method == "POST":
        pass

    elif request.method == "GET":
        pass


@app.route("/<election_uuid>/trustee/<trustee_uuid>/step2", methods=["GET", "POST"])
def truustee_step_2(election_uuid: str, trustee_uuid: str) -> Response:
    """
    Step 2 of the keygenerator trustee
    """
    if request.method == "POST":
        pass

    elif request.method == "GET":
        pass


@app.route("/<election_uuid>/trustee/<trustee_uuid>/step3", methods=["GET", "POST"])
def truustee_step_3(election_uuid: str, trustee_uuid: str) -> Response:
    """
    Step 3 of the keygenerator trustee
    """
    if request.method == "POST":
        pass

    elif request.method == "GET":
        pass


# Freeze Ballot
@app.route("/<election_uuid>/freeze_ballot", methods=["POST"])
@token_required
def freeze_ballot(current_user: User, election_uuid: str) -> Response:
    """
    Route for freeze ballot
    check if the process can be done
    Require a valid token to access >>> token_required
    """
    pass
