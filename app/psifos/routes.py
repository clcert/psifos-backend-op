import base64
import datetime
from email import message
import os
import uuid
import csv
from io import StringIO

import app.celery_worker.psifos.tasks as tasks
from fastapi import Depends, HTTPException, APIRouter, UploadFile, Request
from sqlalchemy.orm import Session
from app.psifos.crypto.tally.common.decryption.trustee_decryption import TrusteeDecryptions
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote

from app.psifos.model import crud, schemas, models
from app.dependencies import get_db
from app.psifos.psifos_object.questions import Questions
from app.psifos.crypto import elgamal, sharedpoint
from app.psifos.crypto import utils as crypto_utils
from app.psifos import utils as psifos_utils
from app.psifos_auth.auth_bearer import AuthAdmin
from app.psifos_auth.utils import get_auth_election, get_auth_trustee_and_election, get_auth_voter_and_election
from app.psifos_auth.auth_service_check import AuthUser


from starlette_context import context

api_router = APIRouter(prefix="/psifos/api/app")

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
        "status": election.election_status,
        "name": election.short_name
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


@api_router.post("/edit-election/{election_uuid}", status_code=201)
def edit_election(election_uuid: str, election_in: schemas.ElectionIn, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Admin's route for editing an election
    """
    election_exist = crud.get_election_by_short_name(db=db, short_name=election_in.short_name) is not None
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)

    if election_exist and election.short_name != election_in.short_name:
        raise HTTPException(status_code=404, detail="The election already exists.")

    crud.edit_election(db=db, election_id=election.id, election=election_in)
    return {
        "message": "Election edited successfully!",
        "uuid": election.uuid
    }


@api_router.post("/create-questions/{election_uuid}", status_code=200)
def create_questions(election_uuid: str, data_questions: dict, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Admin's route for creating questions for an election
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    questions = Questions(*data_questions["question"])
    crud.edit_questions(db=db, db_election=election, questions=questions)
    return {"message": "Preguntas creadas con exito!"}

@api_router.post("/{election_uuid}/upload-voters", status_code=200)
def upload_voters(election_uuid: str, file: UploadFile, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Admin's route for uploading the voters of an election
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    
    voter_file_content = file.file.read().decode('utf-8')
    task_params = {
        "election_uuid": election.uuid,
        "voter_file_content": voter_file_content,
    }
    task = tasks.upload_voters.delay(**task_params)
    status, voter_counter, total_voters = task.get()

    if status:
        return {
            "message": f"[{voter_counter}/{total_voters}] voters were successfully uploaded"
        }
    else: 
        raise HTTPException(status_code=400, detail="Failed to upload the voters")
    

@api_router.post("/{election_uuid}/get-voters", response_model=list[schemas.VoterOut], status_code=200)
def get_voters(election_uuid: str, data: dict = {},  current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for get voters
    """

    page = data.get("page", 0)
    page_size = data.get("page_size", None)

    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    return crud.get_voters_by_election_id(db=db, election_id=election.id, page=page, page_size=page_size)

@api_router.post("/{election_uuid}/voters/{voter_uuid}/edit", response_model=schemas.VoterOut, status_code=200)
def edit_voter(election_uuid: str, voter_uuid: str, fields_voter: dict, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for get a voter
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    return crud.edit_voter(voter_uuid=voter_uuid, db=db, election_id=election.id, fields=fields_voter)


@api_router.post("/{election_uuid}/delete-voters", status_code=200)
def delete_voters(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for delete voters
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    crud.delete_election_voters(db=db, election_id=election.id)

@api_router.post("/{election_uuid}/voter/{voter_uuid}/delete")
def delete_voter(election_uuid: str, voter_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for delete a voter
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    crud.delete_election_voter(db=db, election_id=election.id, voter_uuid=voter_uuid)


@api_router.get("/{election_uuid}/resume", status_code=200)
def resume(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for get a resume election
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    return {
        "weights_init": election.voters_by_weight_init,
        "weights_end": election.voters_by_weight_end
    }

@api_router.post("/{election_uuid}/start-election", status_code=200)
def start_election(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for starting an election, once it happens the election
    gets "frozen" which means it shouldn't be modified from now on.
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    crud.update_election(db=db, election_id=election.id, fields=election.start())
    return {
        "message": "The election was succesfully started" 
    }


@api_router.post("/{election_uuid}/end-election", status_code=200)
def end_election(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for ending an election, once it happens no voter
    should be able to cast a vote.
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    crud.update_election(db=db, election_id=election.id, fields=election.end())
    return {
        "message": "The election was succesfully ended"
    }


@api_router.post("/{election_uuid}/compute-tally", status_code=200)
def compute_tally(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for freezing an election
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    voters = crud.get_voters_by_election_id(db=db, election_id=election.id)
    
    not_null_voters = [v for v in voters if v.cast_vote.valid_cast_votes >= 1]
    serialized_encrypted_votes = [EncryptedVote.serialize(v.cast_vote.vote) for v in not_null_voters]
    weights = [v.voter_weight for v in not_null_voters]

    task_params = {
        "election_uuid": election.uuid,
        "serialized_encrypted_votes": serialized_encrypted_votes,
        "weights": weights,
    }
    
    tasks.compute_tally.delay(**task_params)

    return {
        "message": "The encrypted tally was succesfully computed"
    }

@api_router.post("/{election_uuid}/combine-decryptions", status_code=200)
def combine_decryptions(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for freezing an election
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)

    task_params = {
        "election_uuid": election.uuid,
    }
    tasks.combine_decryptions.delay(**task_params)
    
    return {
        "message": "Se han combinado las desencriptaciones parciales y el resultado ha sido calculado"
    }


@api_router.get("/{election_uuid}/get-trustees", status_code=200, response_model=list[schemas.TrusteeOut])
def get_trustees(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for get trustees
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    return crud.get_trustees_by_election_id(db=db, election_id=election.id)

@api_router.post("/{election_uuid}/create-trustee", status_code=200)
def create_trustee(election_uuid: str, trustee_in: schemas.TrusteeIn, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for create trustee
    Require a valid token to access >>> token_required
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    crud.create_trustee(
        db=db,
        election_id=election.id,
        uuid=str(uuid.uuid1()),
        trustee_id=crud.get_next_trustee_id(db=db, election_id=election.id),
        trustee=trustee_in
    )
    crud.update_election(
        db=db,
        election_id=election.id,
        fields={"total_trustees": election.total_trustees + 1}
    )
    return {"message": "The trustee was successfully created"}


@api_router.post("/{election_uuid}/delete-trustee/{trustee_uuid}", status_code=200)
def delete_trustee(election_uuid: str, trustee_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Route for delete trustee
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    crud.delete_trustee(db=db, election_id=election.id, uuid=trustee_uuid)
    crud.update_election(
        db=db,
        election_id=election.id,
        fields={"total_trustees": election.total_trustees - 1}
    )
    return {"message": "The trustee was successfully deleted"}


# ----- Voter Routes ----- 

@api_router.post("/{election_uuid}/cast-vote", status_code=200)
def cast_vote(request: Request, election_uuid: str, cast_vote: schemas.CastVoteIn, voter_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Route for casting a vote
    """

    voter, election = get_auth_voter_and_election(db=db, election_uuid=election_uuid, voter_login_id=voter_login_id)
    
    # >>> Los checks de Helios podemos hacerlos con dependencias de FastAPI <<<
    # allowed, msg = psifos_utils.do_cast_vote_checks(request, election, voter)
    # if not allowed:
    #    return make_response(jsonify({"message": f"{msg}"}), 400)

    serialized_encrypted_vote = cast_vote.encrypted_vote
    cast_ip = request.client.host

    task_params = {
        "election_uuid": election.uuid,
        "serialized_encrypted_vote": serialized_encrypted_vote,
        "voter_id": voter.id,
        "cast_ip":cast_ip,
    }
    
    task = tasks.process_cast_vote.delay(**task_params)
    verified, vote_fingerprint = task.get()

    if verified:
        return {
            "message": "Encrypted vote recieved succesfully",
            "verified": verified,
            "vote_hash": vote_fingerprint
        }
    else:
        return {
            "message": "Invalid encrypted vote",
            "verified": verified
        }

        

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
def get_trustee_home(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Trustee's route for getting his home
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)

    return schemas.TrusteeHome(trustee=schemas.TrusteeOut.from_orm(trustee), election=schemas.ElectionOut.from_orm(election))


@api_router.get("/{election_uuid}/get-randomness", status_code=200)
def get_randomness(election_uuid: str, _ : str = Depends(AuthUser())):
    """
    Get some randomness to sprinkle into the sjcl entropy pool
    """
    return {"randomness": base64.b64encode(os.urandom(32)).decode("utf-8")}



# Routes for keygenerator trustee (Trustee Stage 1)


@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/get-step", status_code=200)
def get_step(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Get the step of the trustee
    """
    _, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    trustee_step = crud.get_global_trustee_step(
        db=db,
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
def trustee_upload_pk(election_uuid: str, trustee_uuid: str, trustee_data: schemas.PublicKeyData, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
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
def post_trustee_step_1(election_uuid: str, trustee_uuid: str, trustee_data: schemas.KeyGenStep1Data, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Step 1 of the keygenerator trustee
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(db=db, election_id=election.id)
    if global_trustee_step != 1:
        raise HTTPException(status_code=400, detail="The election's global trustee step is not 1")

    # Instantiate coefficients
    coeffs_data = psifos_utils.from_json(trustee_data.coefficients)
    coefficients = sharedpoint.ListOfCoefficients(*coeffs_data)
    # Instantiate points
    points_data = psifos_utils.from_json(trustee_data.points)
    points = [sharedpoint.Point(**params) for params in points_data]

    # TODO: perform server-side checks here!
    crud.delete_shared_points_by_sender(db=db, sender=trustee.trustee_id)
    crud.create_shared_points(db=db, election_id=election.id, sender=trustee.trustee_id, points=points)
    
    crud.update_trustee(db=db, trustee_id=trustee.id, fields={"coefficients": coefficients, "current_step": 2})

    return {"message": "Keygenerator step 1 completed successfully"}


@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/step-1", status_code=200)
def get_trustee_step_1(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Step 1 of the keygenerator trustee
    """
    _, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(db=db, election_id=election.id)
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
def post_trustee_step_2(election_uuid: str, trustee_uuid: str, trustee_data: schemas.KeyGenStep2Data, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Step 2 of the keygenerator trustee
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(db=db, election_id=election.id)
    if global_trustee_step != 2:
        raise HTTPException(status_code=400, detail="The election's global trustee step is not 2")

    acks_data = psifos_utils.from_json(trustee_data.acknowledgements)
    acks = sharedpoint.ListOfSignatures(*acks_data)

    # TODO: perform server-side checks here!
    crud.update_trustee(db=db, trustee_id=trustee.id, fields={"acknowledgements": acks, "current_step": 3})

    return {"message": "Keygenerator step 2 completed successfully"}
    

@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/step-2", status_code=200)
def get_trustee_step_2(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Step 2 of the keygenerator trustee
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(db=db, election_id=election.id)
    if global_trustee_step != 2:
        raise HTTPException(status_code=400, detail="The election's global trustee step is not 2")

    try:    
        params = election.get_eg_params()
        trustees = crud.get_trustees_by_election_id(db=db, election_id=election.id)
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
            db=db,
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
def post_trustee_step_3(election_uuid: str, trustee_uuid: str, trustee_data: schemas.KeyGenStep3Data, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Step 3 of the keygenerator trustee
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(db=db, election_id=election.id)
    if global_trustee_step != 3:
        raise HTTPException(status_code=400, detail="The election's global trustee step is not 3")

    pk_data = psifos_utils.from_json(trustee_data.verification_key)
    pk = elgamal.PublicKey(**pk_data)

    # TODO: perform server-side checks here!
    crud.update_trustee(db=db, trustee_id=trustee.id, fields={"public_key": pk, "current_step": 4})

    return {"message": "Keygenerator step 3 completed successfully"}

        

@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/step-3", status_code=200)
def post_trustee_step_3(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Step 3 of the keygenerator trustee
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = crud.get_global_trustee_step(db=db, election_id=election.id)
    if global_trustee_step != 3:
        raise HTTPException(status_code=400, detail="The election's global trustee step is not 3")

    try:
        params = election.get_eg_params()
        trustees = crud.get_trustees_by_election_id(db=db, election_id=election.id)

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
            db=db,
            election_id=election.id,
            trustee_id=trustee.trustee_id,
        )

        points_sent = crud.format_points_sent_by(
            db=db,
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
def trustee_check_sk(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Trustee Stage 2
    """
    trustee, _ = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    return sharedpoint.Certificate.serialize(trustee.certificate, to_json=False)

@api_router.post("/{election_uuid}/trustee/{trustee_uuid}/decrypt-and-prove", status_code=200)
def trustee_decrypt_and_prove(election_uuid: str, trustee_uuid: str, trustee_data: schemas.DecryptionIn, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
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
        
        if election.decryptions_uploaded == election.total_trustees:
            crud.update_election(db=db, election_id=election.id, fields={"election_status": "decryptions_uploaded"})
        
        return {"message": "Trustee's stage 3 completed successfully"}

    else:
        raise HTTPException(status_code=400, detail="An error was found during the verification of the proofs")

@api_router.get("/{election_uuid}/trustee/{trustee_uuid}/decrypt-and-prove", status_code=200)
def trustee_decrypt_and_prove(election_uuid: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Trustee Stage 3
    """
    trustee, election = get_auth_trustee_and_election(db=db, election_uuid=election_uuid, trustee_uuid=trustee_uuid, login_id=trustee_login_id)

    params = election.get_eg_params()
    trustees = crud.get_trustees_by_election_id(db=db, election_id=election.id)
    certificates = [sharedpoint.Certificate.serialize(t.certificate, to_json=False) for t in trustees]
    points = crud.format_points_sent_to(
        db=db,
        election_id=election.id,
        trustee_id=trustee.trustee_id,
    )
    return {
        "election": schemas.ElectionOut.from_orm(election),
        "trustee": schemas.TrusteeOut.from_orm(trustee),
        "params": params,
        "certificates": psifos_utils.to_json(certificates),
        "points": psifos_utils.to_json(points),
    }


# >>> Revisar
@api_router.get("/{election_uuid}/questions", status_code=200, response_model=schemas.ElectionOut)
def get_questions_voters(election_uuid: str,  voter_login_id: str = Depends(AuthUser()), db: Session = Depends(get_db)):
    """
    Route for get questions
    """

    _, election = get_auth_voter_and_election(db=db, election_uuid=election_uuid, voter_login_id=voter_login_id)

    return election

@api_router.get("/{election_uuid}/questions", status_code=200)
def get_questions(election_uuid: str, current_user: models.User = Depends(AuthAdmin()), db: Session = Depends(get_db)):
    """
    Admin's route for getting all the questions of a specific election
    """
    election = get_auth_election(election_uuid=election_uuid, current_user=current_user, db=db)
    if not election.questions:
        HTTPException(status_code=400, detail="The election doesn't have questions")

    return Questions.serialize(election.questions)
# <<<