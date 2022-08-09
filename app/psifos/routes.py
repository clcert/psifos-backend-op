import base64
import os
from unicodedata import name
from urllib import response
import uuid
import csv

from fastapi import Depends, HTTPException, APIRouter, UploadFile
from sqlalchemy.orm import Session
from app.psifos.crypto.tally.common.decryption.trustee_decryption import TrusteeDecryptions

from app.psifos.model import crud, schemas, models
from app.dependencies import get_db
from app.psifos.psifos_object.questions import Questions
from app.psifos.crypto import elgamal, sharedpoint
from app.psifos.crypto import utils as crypto_utils
from app.psifos import utils as psifos_utils
from app.psifos_auth.auth_bearer import AuthAdmin
from app.psifos_auth.utils import get_auth_election, get_auth_trustee_and_election

api_router = APIRouter()

# ----- Election Admin Routes -----

@api_router.post("/create-election", status_code=201)
def create_election(
    election_in: schemas.ElectionIn,
    current_user: models.User = Depends(AuthAdmin()),
    db: Session = Depends(get_db)
):
    """
    Admin's route for creating an election
    """
    election_exists = crud.get_election_by_short_name(short_name=election_in.short_name, db=db) is not None
    if election_exists:
        raise HTTPException(status_code=404, detail="The election already exists.")

    uuid_election = str(uuid.uuid4())
    crud.create_election(db=db, election=election_in, admin_id=current_user.get_id(), uuid=uuid_election)
    return {"message": "Elección creada con exito!", "uuid": uuid_election}


@api_router.get("/get-election/{election_uuid}", response_model=schemas.ElectionOut, status_code=200)
def get_election(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Admin's route for getting a specific election by uuid
    """
    return get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)


@api_router.get("/get-election-stats/{election_uuid}", status_code=200)
def get_election_stats(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Admin's route for getting the stats of a specific election.
    """
    election = get_auth_election(election_uuid = election_uuid, current_user=current_user, db=db)
    return {
        "num_casted_votes": crud.get_num_casted_votes(
            db=db,
            election_id=election.id
        ),
        "total_voters": election.total_voters,
    }


@api_router.get("/get-elections", response_model=list[schemas.ElectionOut], status_code=200)
def get_elections(current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Admin's route for getting all elections administered by him
    """
    return [
        election for election 
        in crud.get_elections_by_user(
            db=db, 
            admin_id=current_user.get_id()
        )
    ]


@api_router.post("/edit-election/{election_uuid}", status_code=200)
def edit_election(election_uuid: str, electionIn: schemas.ElectionIn, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Admin's route for editing an election
    """
    election_exist = crud.get_election_by_short_name(short_name=electionIn.short_name) is not None
    if election_exist:
        raise HTTPException(status_code=404, detail="The election already exists.")

    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    crud.edit_election(db=db, election_id=election.id, election=electionIn)
    return {"message": "Election edited successfully!"}


@api_router.post("/create-questions/{election_uuid}", status_code=200)
def create_questions(election_uuid: str, data_questions: dict, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Admin's route for creating questions for an election
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    questions = Questions(*data_questions["question"])
    crud.edit_questions(db=db, db_election=election, questions=questions)
    return {"message": "Preguntas creadas con exito!"}

@api_router.get("/get-questions/{election_uuid}", status_code=200)
def get_questions(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Admin's route for getting all the questions of a specific election
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    if not election.questions:
        HTTPException(status_code=400, detail="The election doesn't have questions")

    return Questions.serialize(election.questions)


@api_router.post("/{election_uuid}/upload-voters", status_code=200)
def upload_voters(election_uuid: str, voter_file: UploadFile(), current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Admin's route for uploading the voters of an election
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    try:
        csv_reader = csv.reader(voter_file.file, delimiter=',')
        voters: list[schemas.VoterIn] = [
            schemas.VoterIn(voter_login_id=login_id, voter_weight=weight, voter_name=name)
            for login_id, weight, name in csv_reader
        ]
        total_voters = len(voters)

        # TODO: make it async
        for voter in voters:
            crud.create_voter(db=db, voter=voter)
        
        crud.update_election(db=db, election_id=election.id, fields={"total_voters":total_voters})
    
    except:
        raise HTTPException(status_code=400, detail="Failed to upload the voters")


@api_router.get("/{election_uuid}/get-voters", response_model=list[schemas.VoterOut], status_code=200)
def get_voters(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for get voters
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    return crud.get_voters_by_election_id(db=db, election_id=election.id)


@api_router.post("/{election_uuid}/delete-voters", status_code=200)
def delete_voters(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for delete voters
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    crud.delete_election_voters(db=db, election_id=election.id)


@api_router.get("/{election_uuid}/resume")
def resume(current_user: User, election_uuid: str, db: Session = Depends(get_db)):
    """
    Route for get a resume election
    Require a valid token to access >>> token_required
    """
    try:
        election = Election.get_by_uuid(uuid=election_uuid)
        voters_election = Voter.filter_by(election_id=election.id)
        if election.admin_id == current_user.get_id():

            return make_response(
                jsonify({"weights_init": election.voters_by_weight_init, 
                         "weights_end": election.voters_by_weight_end
                         }), 200
            )
        else:
            return make_response(
                jsonify({"message": "No tiene permisos ver esta elección"}), 401
            )

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Error al acceder al resumen de la elección"}), 400)


@api_router.post("/{election_uuid}/start-election", methods=["POST"])
def start_election(election_uuid: str, db: Session = Depends(get_db)):
    """
    Route for starting an election, once it happens the election
    gets "frozen" which means it shouldn't be modified from now on.
    Require a valid token to access >>> token_required
    """
    try:
        trustees = Trustee.get_by_election(election_id=election.id)
        voters = Voter.get_by_election(election_id=election.id)
        election.start(trustees=trustees, voters=voters)
        return make_response(jsonify({"message": "Eleccion iniciada con exito!"}), 200)
    
    except:
        return make_response(jsonify({"message": "Error al iniciar la eleccion!"}), 400)


@api_router.post("/{election_uuid}/end-election", methods=["POST"])
def end_election(election_uuid: str, db: Session = Depends(get_db)):
    """
    Route for ending an election, once it happens no voter
    should be able to cast a vote.
    Require a valid token to access >>> token_required
    """
    try:
        voters = Voter.get_by_election(election_id=election.id)
        not_null_voters = [v for v in voters if v.cast_vote.valid_cast_votes >= 1]
        election.end(voters=not_null_voters)
        return make_response(jsonify({"message": "Eleccion terminada con exito!"}), 200)
    
    except:
        return make_response(jsonify({"message": "Error al terminar la eleccion!"}), 400)


@api_router.post("/{election_uuid}/compute-tally", methods=["POST"])
def compute_tally(election_uuid: str, db: Session = Depends(get_db)):
    """
    Route for freezing an election
    Require a valid token to access >>> token_required
    """
    try:
        voters = Voter.get_by_election(election_id=election.id)
        not_null_voters = [v for v in voters if v.cast_vote.valid_cast_votes >= 1]

        encrypted_votes = [v.cast_vote.vote for v in not_null_voters]
        weights = [v.voter_weight for v in not_null_voters]
        election.compute_tally(encrypted_votes, weights)
        return make_response(jsonify({"message": "Se computado el tally de la eleccion con exito!"}), 200)
    except:
        return make_response(jsonify({"message": "Error al computar el tally de la eleccion"}), 400)

@api_router.post("/{election_uuid}/combine-decryptions", methods=["POST"])
def combine_decryptions(election_uuid: str, db: Session = Depends(get_db)):
    """
    Route for freezing an election
    Require a valid token to access >>> token_required
    """
    
    trustees = Trustee.get_by_election(election.id)
    election.combine_decryptions(trustees)
    return make_response(jsonify({"message": "Se han combinado las desencriptaciones parciales y el resultado ha sido calculado"}), 200)
    # except:
    #     return make_response(jsonify({"message": "Error al combinar las desencriptaciones parciales"}), 400)


@api_router.get("/{election_uuid}/get-trustees", methods=["GET"])
@token_required
def get_trustees(current_user: User, election_uuid: str, db: Session = Depends(get_db)):
    """
    Route for get trustees
    Require a valid token to access >>> token_required
    """
    try:
        election = Election.get_by_uuid(uuid=election_uuid)
        if election.admin_id == current_user.get_id():
            trustees = Trustee.filter_by(election_id=election.id)
            result = [Trustee.to_dict(schema=trustee_schema, obj=e) for e in trustees]
            response = make_response(jsonify(result), 200)
            return response
        else:
            return make_response(
                jsonify({"message": "No tiene permisos para obtener los trustees"}), 401
            )
    except:
        return make_response(jsonify({"message": "Error al obtener los trustees"}), 400)

@api_router.post("/{election_uuid}/create-trustee", methods=["POST"])
def create_trustee(current_user: User, election_uuid: str, db: Session = Depends(get_db)):
    """
    Route for create trustee
    Require a valid token to access >>> token_required
    """
    try:
        data = request.get_json()
        election = Election.get_by_uuid(uuid=election_uuid)
        if election.admin_id == current_user.get_id():
            Trustee.update_or_create(
                election_id=election.id,
                uuid=str(uuid.uuid1()),
                name=data["name"],
                trustee_id=Trustee.get_next_trustee_id(election.id),
                trustee_login_id=data["trustee_login_id"],
                email=data["email"],
            )
            election.total_trustees += 1
            PsifosModel.commit()
            return make_response(jsonify({"message": "Creado con exito!"}), 200)
        else:
            return make_response(
                jsonify({"message": "No tiene permisos para crear un trustee"}), 401
            )
    except:
        return make_response(jsonify({"message": "Error al crear el trustee"}), 400)


@api_router.post("/{election_uuid}/delete-trustee", methods=["POST"])
def delete_trustee(current_user: User, election_uuid: str, db: Session = Depends(get_db)):
    """
    Route for delete trustee
    Require a valid token to access >>> token_required
    """
    try:
        data = request.get_json()
        election = Election.get_by_uuid(uuid=election_uuid)
        if election.admin_id == current_user.get_id():
            trustee = Trustee.get_by_uuid(uuid=data["uuid"])
            PsifosModel.delete(trustee)
            return make_response(jsonify({"message": "Eliminado con exito!"}), 200)
        else:
            return make_response(
                jsonify({"message": "No tiene permisos para eliminar un trustee"}), 401
            )
    except:
        return make_response(jsonify({"message": "Error al eliminar el trustee"}), 400)


# ----- Voter Routes ----- 

@api_router.post("/{election_uuid}/cast-vote", status_code=200)
def cast_vote(election_uuid: str, voter: Voter, db: Session = Depends(get_db)):
    """
    Route for casting a vote
    Require a valid token to access >>> token_required
    """
   
    allowed, msg = psifos_utils.do_cast_vote_checks(request, election, voter)
    if not allowed:
        return make_response(jsonify({"message": f"{msg}"}), 400)

    
    data = psifos_utils.from_json(request.get_json())
    enc_vote_data = psifos_utils.from_json(data["encrypted_vote"])
    encrypted_vote = EncryptedVote(**enc_vote_data)

    # FIXME: -- verify asynchronously --
    if not encrypted_vote.verify(election):
        voter.cast_vote.invalid_cast_votes += 1
        voter.cast_vote.invalidated_at = datetime.now()
        return make_response(jsonify({"message": "El voto enviado no es valido"}), 400)
    else:
        voter.cast_vote.verified_at = datetime.now()

    PsifosModel.add(voter)
    PsifosModel.commit()

    vote_fingerprint = crypto_utils.hash_b64(EncryptedVote.serialize(encrypted_vote)) #)
    cast_ip = request.headers.getlist("X-Forwarded-For")[0] if ("X-Forwarded-For" in request.headers) else request.remote_addr
    ip_fingerprint = crypto_utils.hash_b64(cast_ip)

    cv_params = {
        "voter_id": voter.id,
        "vote": encrypted_vote,
        "vote_hash": vote_fingerprint,
        "cast_at": datetime.now(),
        "cast_ip": cast_ip,
        "ip_fingerprint": ip_fingerprint,
    }

    cast_vote = CastVote.update_or_create(**cv_params)
    cast_vote.valid_cast_votes += 1
    PsifosModel.commit()
    return make_response(jsonify({"message": "Voto registrado con exito.", "vote_hash": vote_fingerprint}), 200)

        










@api_router.get("/{election_uuid}/questions", status_code=200)
def get_questions_voters(election_uuid: str, voter: Voter, db: Session = Depends(get_db)):
    """
    Route for get questions
    Require a cookie valid in session >>> CAS
    """

    result = Election.to_dict(schema=election_schema, obj=election)
    return create_response_cors(make_response(result, 200))


# ----- Trustee Routes -----

@api_router.get("/{trustee_uuid}/get-trustee", status_code=200, response_model=schemas.TrusteeOut)
def get_trustee(trustee_uuid, db: Session = Depends(get_db)):
    """
    Route for getting a trustee
    """
    try:
        return crud.get_trustee_by_uuid(uuid=trustee_uuid)
    except:
        raise HTTPException(status_code=400, detail="Error al obtener el trustee")


@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/home", status_code=200, response_model=schemas.TrusteeHome)
def get_trustee_home(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Trustee's route for getting his home
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)

    return schemas.TrusteeHome(trustee=trustee, election=election)


@api_router.get("/{election_uuid}/get-randomness", status_code=200)
def get_randomness(election_uuid: str, _ : str = Depends(get_login_id)):
    """
    Get some randomness to sprinkle into the sjcl entropy pool
    """
    return {"randomness": base64.b64encode(os.urandom(32)).decode("utf-8")}



# Routes for keygenerator trustee (Trustee Stage 1)


@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/get-step", status_code=200)
def get_step(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Get the step of the trustee
    """
    _, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    trustee_step = crud.get_global_trustee_step(
        election_id=election.id
    )

    return {
        "message": "Step del trustee obtenido con exito!",
        "status": trustee_step,
    }


@api_router.get("/{election_uuid}/get-eg-params", status_code=200)
def election_get_eg_params(election_uuid: str, db: Session = Depends(get_db)):
    """
    Returns a JSON with the election eg_params.
    """
    try:
        election = crud.get_election_by_uuid(db=db, uuid=election_uuid)
        return election.get_eg_params()

    except:
        raise HTTPException(status_code=400, detail="Error al obtener los parametros de la eleccion.")


@api_router.post("/{election_uuid}/trustee/{trustee_uuid}/upload-pk", status_code=200)
def trustee_upload_pk(election_uuid: str, trustee_uuid: str, trustee_data: schemas.PublicKeyData, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Upload public key of trustee
    """
    trustee, _ = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)

    public_key_and_proof = psifos_utils.from_json(trustee_data.public_key_json)

    # TODO: validate certificate
    cert = sharedpoint.Certificate(**public_key_and_proof)

    # setting trustee's certificate and pk hash.
    trustee.certificate = cert
    trustee.public_key_hash = crypto_utils.hash_b64(str(cert.signature_key))

    # as uploading the pk is the "step 0", we need to update the current_step
    crud.update_trustee(db=db, trustee_id=trustee.id, fields={"current_step":1})
    
    return {"message": "The certificate of the trustee was uploaded successfully"}


@api_router.post("/{election_uuid}/trustee/{trustee_uuid}/step-1", status_code=200)
def post_trustee_step_1(election_uuid: str, trustee_uuid: str, trustee_data: schemas.KeyGenStep1Data, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Step 1 of the keygenerator trustee
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(election_id=election.id)
    if global_trustee_step != 1:
        raise HTTPException(status_code=400, detail="The election's global trustee step is not 1")

    # Instantiate coefficients
    coeffs_data = psifos_utils.from_json(trustee_data.coefficients)
    coefficients = sharedpoint.ListOfCoefficients(*coeffs_data)
    # Instantiate points
    points_data = psifos_utils.from_json(trustee_data.points)
    points = [sharedpoint.Point(**params) for params in points_data]

    # TODO: perform server-side checks here!
    crud.crud.delete_shared_points_by_sender(db=db, sender=trustee.trustee_id)
    crud.create_shared_points(db=db, election_id=election.id, sender=trustee.trustee_id, points=points)
    
    crud.update_trustee(db=db, trustee_id=trustee.id, fields={"coefficients": coefficients, "current_step": 2})

    return {"message": "Keygenerator step 1 completed successfully"}


@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/step-1", status_code=200)
def get_trustee_step_1(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Step 1 of the keygenerator trustee
    """
    _, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(election_id=election.id)
    if global_trustee_step != 1:
        raise HTTPException(status_code=400, detail="The election's global trustee step is not 1")

    try:
        params = election.get_eg_params()
        trustees = crud.get_trustees_by_election_id(db=db, election_id=election.id)
        certificates = [
            sharedpoint.Certificate.serialize(t.certificate, to_json=False)
            for t in trustees
        ]
        assert None not in certificates

        return {
            "params": params,
            "certificates": psifos_utils.to_json(certificates),
        }

    except:
        raise HTTPException(status_code=400, detail="Some trustees haven't generated their keypair")


@api_router.post("/{election_uuid}/trustee/{trustee_uuid}/step-2", status_code=200)
def post_trustee_step_2(election_uuid: str, trustee_uuid: str, trustee_data: schemas.KeyGenStep2Data, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Step 2 of the keygenerator trustee
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(election_id=election.id)
    if global_trustee_step != 2:
        raise HTTPException(status_code=400, detail="The election's global trustee step is not 2")

    acks_data = psifos_utils.from_json(trustee_data.acknowledgements)
    acks = sharedpoint.ListOfSignatures(*acks_data)

    # TODO: perform server-side checks here!
    crud.update_trustee(db=db, trustee_id=trustee.id, fields={"acknowledgement": acks, "current_step": 3})

    return {"message": "Keygenerator step 2 completed successfully"}
    

@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/step-2", status_code=200)
def get_trustee_step_2(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Step 2 of the keygenerator trustee
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(election_id=election.id)
    if global_trustee_step != 2:
        raise HTTPException(status_code=400, detail="The election's global trustee step is not 2")

    try:
        params = election.get_eg_params()
        trustees = crud.get_trustees_by_election_id(election_id=election.id)
        coefficients = [
            sharedpoint.ListOfCoefficients.serialize(t.coefficients, to_json=False)
            for t in trustees
        ]
        assert None not in coefficients

        certificates = [
            sharedpoint.Certificate.serialize(t.certificate, to_json=False)
            for t in trustees
        ]
        assert None not in certificates

        points = crud.format_points_sent_to(
            election_id=election.id,
            trustee_id=trustee.trustee_id,
        )

        return {
            "params": params,
            "certificates": psifos_utils.to_json(certificates),
            "coefficients": psifos_utils.to_json(coefficients),
            "points": psifos_utils.to_json(points),
        }

    except:
        raise HTTPException(status_code=400, detail="Some trustees haven't completed the step 1 of the key generator")


@api_router.post("/{election_uuid}/trustee/{trustee_uuid}/step-3", status_code=200)
def post_trustee_step_3(election_uuid: str, trustee_uuid: str, trustee_data: schemas.KeyGenStep3Data, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Step 3 of the keygenerator trustee
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(election_id=election.id)
    if global_trustee_step != 3:
        raise HTTPException(status_code=400, detail="The election's global trustee step is not 3")

    pk_data = psifos_utils.from_json(trustee_data.verification_key)
    pk = elgamal.PublicKey(**pk_data)

    # TODO: perform server-side checks here!
    crud.update_trustee(db=db, trustee_id=trustee.id, fields={"public_key": pk, "current_step": 4})

    return {"message": "Keygenerator step 3 completed successfully"}

        

@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/step-3", status_code=200)
def post_trustee_step_3(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Step 3 of the keygenerator trustee
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(election_id=election.id)
    if global_trustee_step != 3:
        raise HTTPException(status_code=400, detail="The election's global trustee step is not 3")

    try:
        params = election.get_eg_params()
        trustees = crud.get_trustees_by_election_id(election_id=election.id)

        coefficients = [
            sharedpoint.ListOfCoefficients.serialize(t.coefficients, to_json=False)
            for t in trustees
        ]
        assert None not in coefficients

        acks_trustees = [
            sharedpoint.ListOfSignatures.serialize(t.acknowledgements, to_json=False) 
            for t in trustees
        ]
        assert None not in acks_trustees
        ack_indx = trustee.trustee_id - 1
        acknowledgements = [acks[ack_indx] for acks in acks_trustees]

        certificates = [
            sharedpoint.Certificate.serialize(t.certificate, to_json=False)
            for t in trustees
        ]
        assert None not in certificates

        points = crud.format_points_sent_to(
            election_id=election.id,
            trustee_id=trustee.trustee_id,
        )

        points_sent = crud.format_points_sent_by(
            election_id=election.id,
            trustee_id=trustee.trustee_id,
        )

        return {
            "params": params,
            "certificates": psifos_utils.to_json(certificates),
            "coefficents": psifos_utils.to_json(coefficients),
            "points": psifos_utils.to_json(points),
            "acks": psifos_utils.to_json(acknowledgements),
            "points_sent": psifos_utils.to_json(points_sent),
        }

    except:
        raise HTTPException(status_code=400, detail="Some trustees haven't completed the step 2 of the key generator")


@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/check-sk", status_code=200)
def trustee_check_sk(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Trustee Stage 2
    """
    trustee, _ = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    return sharedpoint.Certificate.serialize(trustee.certificate, to_json=False)

@api_router.post("/{election_uuid}/trustee/{trustee_uuid}/decrypt-and-prove", status_code=200)
def trustee_decrypt_and_prove(election_uuid: str, trustee_uuid: str, trustee_data: schemas.DecryptionIn, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Trustee Stage 3
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)

    decryption_list = psifos_utils.from_json(trustee_data.decryptions)
    answers_decryptions : TrusteeDecryptions = TrusteeDecryptions(*decryption_list)

    if answers_decryptions.verify(encrypted_tally=election.encrypted_tally):
        trustee = crud.update_trustee(db=db, trustee_id=trustee.id, fields={"decryptions": answers_decryptions})
        dec_num = election.decryptions_uploaded + 1
        election = crud.update_election(db=db, election_id=election.id, fields={"decryptions_uploaded": dec_num})
        
        if election.decryptions_uploaded == len(election.trustees):
            crud.update_election(db=db, election_id=election.id, fields={"election_status": "decryptions_uploaded"})
        
        return {"message": "Trustee's stage 3 completed successfully"}

    else:
        raise HTTPException(status_code=400, detail="An error was found during the verification of the proofs")

@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/decrypt-and-prove", status_code=200)
def trustee_decrypt_and_prove(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(get_login_id), db: Session = Depends(get_db)):
    """
    Trustee Stage 3
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)

    params = election.get_eg_params()
    trustees = crud.get_trustees_by_election_id(election_id=election.id)
    certificates = [sharedpoint.Certificate.serialize(t.certificate, to_json=False) for t in trustees]
    points = crud.format_points_sent_to(
        election_id=election.id,
        trustee_id=trustee.trustee_id,
    )
    return {
        "params": params,
        "certificates": psifos_utils.to_json(certificates),
        "points": psifos_utils.to_json(points),
    }