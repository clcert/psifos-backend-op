"""
Routes for Psifos.

24-03-2022
"""

from ast import Pass
import uuid
import base64
import os


from urllib import response
from psifos import config
from flask import request, jsonify, make_response, session
from flask.wrappers import Response

from psifos import app
from psifos import utils as route_utils
from psifos.forms import ElectionForm
from psifos.models import Election, SharedPoint, Voter, User, Trustee, CastVote
from psifos.schemas import (
    election_schema,
    voter_schema,
    cast_vote_schema,
    trustee_schema,
    shared_point_schema,
)
from psifos.psifos_object.questions import Questions
from psifos.psifos_auth.utils import (
    auth_requires,
    election_route,
    get_user,
    token_required,
    trustee_cas,
    create_response_cors,
    verify_voter,
)
from psifos.crypto import sharedpoint
from psifos.crypto import elgamal
from psifos.crypto import utils as crypto_utils
from sqlalchemy import func


# Admin routes


@app.route("/create-election", methods=["POST"])
@token_required
def create_election(current_user: User) -> Response:
    """
    Route for create a new election
    Require a valid token to access >>> token_required

    """

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
            jsonify({"message": "Elección creada con exito!", "uuid": uuid_election}),
            200,
        )

    else:
        return make_response(jsonify({"message": form.errors}), 400)


@app.route("/get-election/<election_uuid>", methods=["GET"])
@token_required
@election_route(election_schema=election_schema)
def get_election(election: Election) -> Response:
    """
    Route for get a election by uuid
    Require a valid token to access >>> token_required
    """

    result = Election.to_dict(schema=election_schema, obj=election)
    response = make_response(result, 200)
    return response


@app.route("/get-elections", methods=["GET"])
@token_required
def get_elections(current_user: User):
    """
    Route for get all elections
    Require a valid token to access >>> token_required
    """

    elections = Election.filter_by(
        schema=election_schema, admin_id=current_user.get_id()
    )
    result = [Election.to_dict(schema=election_schema, obj=e) for e in elections]
    return make_response(jsonify(result), 200)


@app.route("/edit-election/<election_uuid>", methods=["POST"])
@token_required
@election_route(election_schema=election_schema)
def edit_election(election: Election) -> Response:
    """
    Route for edit a election
    Require a valid token to access >>> token_required
    """

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
            uuid=election.uuid,
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
                    "uuid": election.uuid,
                }
            ),
            200,
        )

    else:
        return make_response(jsonify({"message": form.errors}), 400)


@app.route("/create-questions/<election_uuid>", methods=["POST"])
@token_required
@election_route(election_schema=election_schema)
def create_questions(election: Election) -> Response:
    """
    Route for create questions
    Require a valid token to access >>> token_required
    """

    data = request.get_json()
    questions = Questions(*data["question"])
    election.questions = questions
    election.save()
    return make_response(jsonify({"message": "Preguntas creadas con exito!"}), 200)


@app.route("/get-questions/<election_uuid>", methods=["GET"])
@token_required
@election_route(election_schema=election_schema, deserialize_election=True)
def get_questions(election: Election) -> response:
    """
    Route for get questions
    Require a valid token to access >>> token_required

    """

    if not election.questions:
        return make_response(
            {"message": "Esta eleccion no tiene preguntas definidas!"}, 200
        )

    json_questions = Questions.serialize(election.questions)
    return make_response(json_questions, 200)


@app.route("/<election_uuid>/send-voters", methods=["POST"])
@token_required
@election_route(election_schema=election_schema)
def send_voters(election: Election) -> Response:
    """
    Route for send voters
    Require a valid token to access >>> token_required
    """

    file_input = request.files["file"]
    file_str = file_input.read().decode("utf-8")
    strip_lines = [line.strip() for line in file_str.split("\n")]
    data = [x.split(",") for x in strip_lines]
    total_voters = len(data)
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

    election.total_voters = total_voters
    election.save()
    return make_response(jsonify({"message": "Votantes creados con exito!"}), 200)


@app.route("/<election_uuid>/get-voters", methods=["GET"])
@token_required
@election_route(election_schema=election_schema)
def get_voters(election: Election) -> Response:
    """
    Route for get voters
    Require a valid token to access >>> token_required
    """

    voters = Voter.filter_by(schema=voter_schema, election_id=election.id)
    result = [Voter.to_dict(schema=voter_schema, obj=e) for e in voters]
    return make_response(jsonify(result), 200)


@app.route("/<election_uuid>/delete-voters", methods=["POST"])
@token_required
@election_route(election_schema=election_schema)
def delete_voters(election: Election) -> Response:
    """
    Route for delete voters
    Require a valid token to access >>> token_required
    """

    voters = Voter.filter_by(schema=voter_schema, election_id=election.id)
    list(map(lambda x: x.delete(), voters))
    return make_response(jsonify({"message": "Votantes eliminados con exito!"}), 200)


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
@election_route(election_schema=election_schema)
def openreg(election: Election) -> Response:
    """
    Route for open election
    Require a valid token to access >>> token_required
    """

    data = request.get_json()
    election.openreg = data["openreg"]
    election.save()
    return make_response(jsonify({"message": "Elección reanudada con exito!"}), 200)


# Voters routes


@app.route("/<election_uuid>/questions")
@auth_requires
@election_route(election_schema=election_schema, admin_election=False)
def get_questions_voters(election: Election) -> Response:
    """
    Route for get questions
    Require a cookie valid in session >>> CAS

    """

    if verify_voter(get_user(), election.uuid):
        result = Election.to_dict(schema=election_schema, obj=election)
        response = create_response_cors(make_response(result, 200))
        return response


# Trustee Routes


@app.route("/<election_uuid>/create-trustee", methods=["POST"])
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
                trustee_id=Trustee.get_next_trustee_id(trustee_schema, election.id),
                trustee_login_id=data["trustee_login_id"],
                email=data["email"],
            )
            trustee.save()
            election.total_trustees += 1
            election.save()
            return make_response(jsonify({"message": "Creado con exito!"}), 200)
        else:
            return make_response(
                jsonify({"message": "No tiene permisos para crear un trustee"}), 401
            )
    except Exception as e:
        raise e
        return make_response(jsonify({"message": "Error al crear el trustee"}), 400)


@app.route("/<election_uuid>/delete-trustee", methods=["POST"])
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


@app.route("/<election_uuid>/get-trustees", methods=["GET"])
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


@app.route("/<trustee_uuid>/get-trustee", methods=["GET"])
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
@auth_requires
@trustee_cas(election_schema=election_schema, trustee_schema=trustee_schema)
def get_trustee_home(election, trustee):
    """
    Route for get trustee home
    Require a cookie valid in session >>> CAS
    """

    response = create_response_cors(
        make_response(jsonify(Trustee.to_dict(schema=trustee_schema, obj=trustee)), 200)
    )
    return response


@app.route("/<election_uuid>/get-randomness", methods=["GET"])
@auth_requires
@trustee_cas(election_schema=election_schema, trustee_schema=trustee_schema)
def get_randomness(election: Election, trustee: Trustee) -> Response:
    """
    Get some randomness to sprinkle into the sjcl entropy pool

    """
    response = create_response_cors(
        make_response(
            jsonify({"randomness": base64.b64encode(os.urandom(32)).decode("utf-8")}),
            200,
        )
    )

    return response


# Routes for keygenerator trustee (Trustee Stage 1)


@app.route("/<election_uuid>/trustee/<trustee_uuid>/get-step", methods=["GET"])
@auth_requires
@trustee_cas(election_schema=election_schema, trustee_schema=trustee_schema)
def get_step(election: Election, trustee: Trustee) -> Response:
    """
    Get the step of the trustee
    """

    trustee_step = Trustee.get_global_trustee_step(
        trustee_schema=trustee_schema, election_id=election.id
    )

    return create_response_cors(
        make_response(
            jsonify(
                {
                    "message": "Step del trustee obtenido con exito!",
                    "status": trustee_step,
                }
            ),
            200,
        )
    )


@app.route("/<election_uuid>/get-eg-params", methods=["GET"])
def election_get_eg_params(election_uuid: str) -> Response:
    """
    Returns a JSON with the election eg_params.
    """
    try:
        election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
        eg_params = election.get_eg_params()
        return create_response_cors(make_response(eg_params, 200))

    except Exception as e:
        print(e)
        return create_response_cors(
            make_response(
                jsonify({"message": "Error al obtener los parametros de la eleccion."}),
                400,
            )
        )


@app.route("/<election_uuid>/trustee/<trustee_uuid>/upload-pk", methods=["POST"])
@auth_requires
@trustee_cas(election_schema=election_schema, trustee_schema=trustee_schema)
def trustee_upload_pk(election: Election, trustee: Trustee) -> Response:
    """
    Upload public key of trustee
    """

    trustee = Trustee.get_by_uuid(schema=trustee_schema, uuid=trustee.uuid)

    body = request.get_json()
    public_key_and_proof = route_utils.from_json(body["public_key_json"])

    # TODO: validate certificate
    cert = sharedpoint.Certificate(**public_key_and_proof)

    # setting trustee's certificate and pk hash.
    trustee.certificate = cert
    trustee.public_key_hash = crypto_utils.hash_b64(str(cert.signature_key))

    # as uploading the pk is the "step 0", we need to update the current_step
    trustee.current_step = 1
    trustee.save()

    return create_response_cors(
        make_response(
            jsonify({"message": "El certificado del trustee fue subido con exito"}), 200
        )
    )


@app.route("/<election_uuid>/trustee/<trustee_uuid>/step-1", methods=["GET", "POST"])
@auth_requires
@trustee_cas(election_schema=election_schema, trustee_schema=trustee_schema)
def trustee_step_1(election: Election, trustee: Trustee) -> Response:
    """
    Step 1 of the keygenerator trustee
    """
    global_trustee_step = Trustee.get_global_trustee_step(
        trustee_schema=trustee_schema, election_id=election.id
    )
    if global_trustee_step != 1:
        return create_response_cors(
            make_response(
                jsonify({"message": "El step global de los trustees no es 1."}),
                400,
            )
        )

    if request.method == "POST":
        body = request.get_json()

        # Instantiate coefficients
        coeffs_data = route_utils.from_json(body["coefficients"])
        coefficients = sharedpoint.ListOfCoefficients(*coeffs_data)
        # Instantiate points
        points_data = route_utils.from_json(body["points"])
        points = [sharedpoint.Point(**params) for params in points_data]

        # TODO: perform server-side checks here!
        t_sent_points = SharedPoint.get_by_sender(
            schema=shared_point_schema, sender=trustee.trustee_id
        )
        for point in t_sent_points:
            point.delete()

        for i in range(len(points)):
            obj = SharedPoint(
                election_id=election.id,
                sender=trustee.trustee_id,
                recipient=i + 1,
                point=points[i],
            )

            obj.save()
        trustee.coefficients = coefficients
        trustee.current_step = 2  # trustee completed step 1 and now is ready for step 2
        trustee.save()

        return create_response_cors(
            make_response(jsonify({"message": "Step 1 completado con exito!"}), 200)
        )

    if request.method == "GET":
        try:
            params = election.get_eg_params()
            trustees = Trustee.filter_by(
                schema=trustee_schema, election_id=election.id, deserialize=True
            )
            certificates = [
                sharedpoint.Certificate.serialize(obj=t.certificate, to_json=False)
                for t in trustees
            ]
            assert None not in certificates

            return create_response_cors(
                make_response(
                    jsonify(
                        {
                            "params": params,
                            "certificates": route_utils.to_json(certificates),
                        }
                    ),
                    200,
                )
            )

        except:
            return create_response_cors(
                make_response(
                    jsonify({"message": "No todos los custodios generaron la llave"}),
                    400,
                )
            )


@app.route("/<election_uuid>/trustee/<trustee_uuid>/step-2", methods=["GET", "POST"])
@auth_requires
@trustee_cas(election_schema=election_schema, trustee_schema=trustee_schema)
def trustee_step_2(election: Election, trustee: Trustee) -> Response:
    """
    Step 2 of the keygenerator trustee
    """

    global_trustee_step = Trustee.get_global_trustee_step(
        trustee_schema=trustee_schema, election_id=election.id
    )
    if global_trustee_step != 2:
        return create_response_cors(
            make_response(
                jsonify({"message": "El step global de los trustees no es 2."}),
                400,
            )
        )

    if request.method == "POST":
        body = request.get_json()
        acks_data = route_utils.from_json(body["acknowledgements"])
        acks = sharedpoint.ListOfSignatures(*acks_data)

        # TODO: perform server-side checks here!
        trustee.acknowledgements = acks
        trustee.current_step = 3  # trustee completed step 2 and now is ready for step 3
        trustee.save()

        return create_response_cors(
            make_response(jsonify({"message": "Step 2 completado con exito!"}), 200)
        )

    if request.method == "GET":
        try:
            params = election.get_eg_params()
            trustees = Trustee.filter_by(schema=trustee_schema, election_id=election.id)
            coefficents = [route_utils.from_json(t.coefficients) for t in trustees]
            assert None not in coefficents

            certificates = [route_utils.from_json(t.certificate) for t in trustees]
            assert None not in certificates

            points = SharedPoint.format_points_sent_to(
                schema=shared_point_schema,
                election_id=election.id,
                trustee_id=trustee.trustee_id,
            )

            return create_response_cors(
                make_response(
                    jsonify(
                        {
                            "params": params,
                            "certificates": route_utils.to_json(certificates),
                            "coefficients": route_utils.to_json(coefficents),
                            "points": route_utils.to_json(points),
                        }
                    ),
                    200,
                )
            )

        except:
            return create_response_cors(
                make_response(
                    jsonify(
                        {"message": "No todos los custodios completaron la etapa 1"}
                    ),
                    400,
                )
            )


@app.route("/<election_uuid>/trustee/<trustee_uuid>/step-3", methods=["GET", "POST"])
@auth_requires
@trustee_cas(election_schema=election_schema, trustee_schema=trustee_schema)
def trustee_step_3(election: Election, trustee: Trustee) -> Response:
    """
    Step 3 of the keygenerator trustee
    """

    global_trustee_step = Trustee.get_global_trustee_step(
        trustee_schema=trustee_schema, election_id=election.id
    )
    if global_trustee_step != 3:
        return create_response_cors(
            make_response(
                jsonify({"message": "El step global de los trustees no es 1."}),
                400,
            )
        )

    if request.method == "POST":
        body = request.get_json()
        pk_data = route_utils.from_json(body["verification_key"])
        pk = elgamal.PublicKey(**pk_data)

        # TODO: perform server-side checks here!

        trustee.public_key = pk
        trustee.current_step = (
            4  # trustee completed step 3 so the process is completed (step 4)
        )
        trustee.save()

        return create_response_cors(
            make_response(jsonify({"message": "Step 3 completado con exito!"}), 200)
        )

    if request.method == "GET":
        try:
            params = election.get_eg_params()
            trustees = Trustee.filter_by(schema=trustee_schema, election_id=election.id)

            coefficients = [route_utils.from_json(t.coefficients) for t in trustees]
            assert None not in coefficients

            acks_trustees = [
                route_utils.from_json(t.acknowledgements) for t in trustees
            ]
            assert None not in acks_trustees
            ack_indx = trustee.trustee_id - 1
            acknowledgements = [acks[ack_indx] for acks in acks_trustees]

            certificates = [route_utils.from_json(t.certificate) for t in trustees]
            assert None not in certificates

            points = SharedPoint.format_points_sent_to(
                schema=shared_point_schema,
                election_id=election.id,
                trustee_id=trustee.trustee_id,
            )

            points_sent = SharedPoint.format_points_sent_by(
                schema=shared_point_schema,
                election_id=election.id,
                trustee_id=trustee.trustee_id,
            )

            return create_response_cors(
                make_response(
                    jsonify(
                        {
                            "params": params,
                            "certificates": route_utils.to_json(certificates),
                            "coefficents": route_utils.to_json(coefficients),
                            "points": route_utils.to_json(points),
                            "acks": route_utils.to_json(acknowledgements),
                            "points_sent": route_utils.to_json(points_sent),
                        }
                    ),
                    200,
                )
            )

        except:
            return create_response_cors(
                make_response(
                    jsonify(
                        {"message": "No todos los custodios completaron la etapa 2"}
                    ),
                    400,
                )
            )


@app.route("/<election_uuid>/trustee/<trustee_uuid>/check-sk", methods=["GET"])
@auth_requires
@trustee_cas(election_schema=election_schema, trustee_schema=trustee_schema)
def trustee_check_sk(election: Election, trustee: Trustee) -> Response:
    """
    Trustee Stage 2
    """
    return create_response_cors(
        make_response(
            jsonify(
                {
                    "election": Election.to_json(schema=election_schema, obj=election),
                    "trustee": Trustee.to_json(schema=trustee_schema, obj=trustee)
                }
            ),
            200,
        )
    )


@app.route("/<election_uuid>/trustee/<trustee_uuid>/decrypt-and-prove", methods=["GET", "POST"])
@auth_requires
@trustee_cas(
    election_schema=election_schema,
    deserialize_election=True,
    trustee_schema=trustee_schema,
)
def trustee_decrypt_and_prove(election: Election, trustee: Trustee) -> Response:
    """
    Trustee Stage 3
    """

    if request.method == "POST":
        if not (election.questions.check_tally_type("homomorphic") and election.encrypted_tally):
            return create_response_cors(
                make_response(
                    jsonify(
                        {"message": "La eleccion no cumple con los requisitos necesarios"}
                    ),
                    400,
                )
            )

        body = request.get_json()
        factors_and_proofs = route_utils.from_json(body["factors_and_proofs"])
        factors = {}
        proofs = {}
        for key in factors_and_proofs:  # 'answers' or 'open_answers'
            # verify the decryption factors
            factors[key] = elgamal.DecryptionFactors(*factors_and_proofs[key]["decryption_factors"])

            # each proof needs to be deserialized
            proofs[key] = elgamal.DecryptionProofs(*factors_and_proofs[key]["decryption_proofs"])

        trustee.answers_decryption_factors = factors["answers"]
        trustee.answers_decryption_proofs = proofs["answers"]
        if trustee.election.mixnet_open_answers is not None:
            trustee.open_answers_decryption_factors = factors["open_answers"]
            trustee.open_answers_decryption_proofs = proofs["open_answers"]

        if True:  # trustee.verify_decryption_proofs():
            trustee.save()

        else:
            return create_response_cors(
                make_response(
                    jsonify(
                        {"message": "Error al verificar las decryption proofs del trustee"}
                    ),
                    400,
                )
            )

    elif request.method == "GET":
        params = election.get_eg_params()
        trustees = Trustee.filter_by(schema=trustee_schema, election_id=election.id)
        certificates = [route_utils.from_json(t.certificate) for t in trustees]
        points = SharedPoint.format_points_sent_to(
            schema=shared_point_schema,
            election_id=election.id,
            trustee_id=trustee.trustee_id,
        )
        return create_response_cors(
            make_response(
                jsonify(
                    {
                        "params": params,
                        "election": Election.to_json(schema=election_schema, obj=election),
                        "certificates": route_utils.to_json(certificates),
                        "points": route_utils.to_json(points),
                    }
                ),
                200,
            )
        )


# Freeze Ballot
@app.route("/<election_uuid>/freeze-ballot", methods=["POST"])
@token_required
def freeze_ballot(current_user: User, election_uuid: str) -> Response:
    """
    Route for freeze ballot
    check if the process can be done
    Require a valid token to access >> > token_required
    """
    pass
