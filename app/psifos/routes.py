import base64
import os
import uuid
import pdfkit
import qrcode
import urllib.parse
import app.celery_worker.psifos.tasks as tasks
import datetime

from fastapi import Depends, HTTPException, APIRouter, UploadFile, Request, Response
from app.psifos.model.enums import ElectionStatusEnum, ElectionPublicEventEnum
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.psifos.crypto.tally.common.decryption.trustee_decryption import TrusteeDecryptions
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from app.config import APP_FRONTEND_URL

from app.psifos.model import crud, schemas, models
from app.dependencies import get_session
from app.psifos.psifos_object.questions import Questions
from app.psifos.crypto import elgamal, sharedpoint
from app.psifos.crypto import utils as crypto_utils
from app.psifos.crypto.elgamal import PublicKey
from app.psifos import utils as psifos_utils
from app.psifos_auth.auth_bearer import AuthAdmin
from app.psifos_auth.utils import get_auth_election, get_auth_trustee_and_election, get_auth_voter_and_election
from app.psifos_auth.auth_service_check import AuthUser
from sqlalchemy.ext.asyncio import AsyncSession

from datetime import timedelta

from app.logger import psifos_logger

from io import BytesIO
from base64 import b64encode

# api_router = APIRouter(prefix="/psifos/api/app")
api_router = APIRouter()
templates = Jinja2Templates(directory="templates")

# ----- Election Admin Routes -----


@api_router.post("/create-election", status_code=201)
async def create_election(
    election_in: schemas.ElectionIn,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session)
):
    """
    Admin's route for creating an election
    """
    election_exists = await crud.get_election_by_short_name(short_name=election_in.short_name, session=session) is not None
    if election_exists:
        raise HTTPException(
            status_code=404, detail="The election already exists.")

    uuid_election = str(uuid.uuid4())
    await crud.create_election(session=session, election=election_in, admin_id=current_user.get_id(), uuid=uuid_election)
    return {"message": "Elección creada con exito!", "uuid": uuid_election}


@api_router.get("/delete-election/{short_name}", status_code=200)
async def delete_election(short_name: str, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Admin's route for delete a election by uuid
    """

    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)
    await crud.delete_election(session=session, election_id=election.id)
    return {"message": "election delete"}


@api_router.get("/get-election/{short_name}", response_model=schemas.ElectionOut, status_code=200)
async def get_election(short_name: str, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Admin's route for getting a specific election by uuid
    """
    return await get_auth_election(short_name=short_name, current_user=current_user, session=session)


@api_router.get("/get-elections", response_model=list[schemas.ElectionOut], status_code=200)
async def get_elections(current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Admin's route for getting all elections administered by him
    """

    elections = await crud.get_elections_by_user(
        session=session,
        admin_id=current_user.get_id()
    )

    return [
        election for election
        in elections
    ]


@api_router.post("/edit-election/{short_name}", status_code=201)
async def edit_election(short_name: str, election_in: schemas.ElectionIn, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Admin's route for editing an election
    """
    election_exist = await crud.get_election_by_short_name(session=session, short_name=election_in.short_name) is not None
    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)

    if election_exist and election.short_name != election_in.short_name:
        raise HTTPException(
            status_code=404, detail="The election already exists.")

    await crud.edit_election(session=session, election_id=election.id, election=election_in)
    return {
        "message": "Election edited successfully!",
        "uuid": election.uuid
    }


@api_router.post("/create-questions/{short_name}", status_code=200)
async def create_questions(short_name: str, data_questions: dict, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Admin's route for creating questions for an election
    """
    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)
    questions = Questions(*data_questions["question"])
    await crud.edit_questions(session=session, db_election=election, questions=questions)
    return {"message": "Preguntas creadas con exito!"}


@api_router.post("/{short_name}/upload-voters", status_code=200)
async def upload_voters(short_name: str, file: UploadFile, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Admin's route for uploading the voters of an election
    """
    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)

    voter_file_content = file.file.read().decode('utf-8')
    task_params = {
        "election_uuid": election.uuid,
        "voter_file_content": voter_file_content,
    }
    task = tasks.upload_voters.delay(**task_params)
    status, voter_counter, total_voters = task.get()

    if status:
        await psifos_logger.info(election_id=election.id, event=ElectionPublicEventEnum.VOTER_FILE_UPLOADED)
        return {
            "message": f"[{voter_counter}/{total_voters}] voters were successfully uploaded"
        }
    else:
        raise HTTPException(
            status_code=400, detail="Failed to upload the voters")


@api_router.post("/{short_name}/get-voters", response_model=list[schemas.VoterOut], status_code=200)
async def get_voters(short_name: str, data: dict = {},  current_user: models.User = Depends(AuthAdmin()), session: Session = Depends(get_session)):
    """
    Route for get voters
    """

    page = data.get("page", 0)
    page_size = data.get("page_size", None)
    page = page_size * page if page_size else None

    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)
    return await crud.get_voters_by_election_id(session=session, election_id=election.id, page=page, page_size=page_size)


@api_router.post("/{short_name}/voters/{voter_uuid}/edit", response_model=schemas.VoterOut, status_code=200)
async def edit_voter(short_name: str, voter_uuid: str, fields_voter: dict, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for get a voter
    """
    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)
    return await crud.edit_voter(voter_uuid=voter_uuid, session=session, election_id=election.id, fields=fields_voter)


@api_router.post("/{short_name}/delete-voters", status_code=200)
async def delete_voters(short_name: str, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for delete voters
    """
    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)
    await crud.delete_election_voters(session=session, election_id=election.id)
    await psifos_logger.warning(election_id=election.id, event=ElectionPublicEventEnum.ELECTORAL_ROLL_MODIFIED)


@api_router.post("/{short_name}/voter/{voter_uuid}/delete")
async def delete_voter(short_name: str, voter_uuid: str, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for delete a voter
    """
    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)
    await crud.delete_election_voter(session=session, election_id=election.id, voter_uuid=voter_uuid)
    await psifos_logger.warning(election_id=election.id, event=ElectionPublicEventEnum.ELECTORAL_ROLL_MODIFIED, voter_uuid=voter_uuid)


@api_router.post("/{short_name}/start-election", status_code=200)
async def start_election(short_name: str, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for starting an election, once it happens the election
    gets "frozen" which means it shouldn't be modified from now on.
    """
    election = await get_auth_election(
        short_name=short_name,
        current_user=current_user,
        session=session,
        status=ElectionStatusEnum.setting_up
    )
    await crud.update_election(session=session, election_id=election.id, fields=election.start())

    await psifos_logger.info(election_id=election.id, event=ElectionPublicEventEnum.VOTING_STARTED)

    return {
        "message": "The election was succesfully started"
    }


@api_router.post("/{short_name}/end-election", status_code=200)
async def end_election(short_name: str, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for ending an election, once it happens no voter
    should be able to cast a vote.
    """
    election = await get_auth_election(
        short_name=short_name,
        current_user=current_user,
        session=session,
        status=ElectionStatusEnum.started
    )

    voters = await crud.get_voters_by_election_id(session=session, election_id=election.id)
    not_null_voters = [v for v in voters if v.valid_cast_votes >= 1]

    if len(not_null_voters) < 1:
        raise HTTPException(
            status_code=400, detail="There must be at least 1 vote casted to end an election.")

    await crud.update_election(session=session, election_id=election.id, fields=election.end())

    await psifos_logger.info(election_id=election.id, event=ElectionPublicEventEnum.VOTING_STOPPED)

    return {
        "message": "The election was succesfully ended"
    }


@api_router.post("/{short_name}/compute-tally", status_code=200)
async def compute_tally(short_name: str, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for freezing an election
    """
    election = await get_auth_election(
        short_name=short_name,
        current_user=current_user,
        session=session,
        status=ElectionStatusEnum.ended
    )
    voters = await crud.get_voters_by_election_id(session=session, election_id=election.id)

    not_null_voters = [v for v in voters if v.valid_cast_votes >= 1]
    serialized_encrypted_votes = [EncryptedVote.serialize(
        v.cast_vote.vote) for v in not_null_voters]
    weights = [v.voter_weight for v in not_null_voters]

    task_params = {
        "election_uuid": election.uuid,
        "serialized_encrypted_votes": serialized_encrypted_votes,
        "weights": weights,
    }

    tasks.compute_tally.delay(**task_params)

    await psifos_logger.info(election_id=election.id, event=ElectionPublicEventEnum.TALLY_COMPUTED)

    return {
        "message": "The encrypted tally was succesfully computed"
    }


@api_router.post("/{short_name}/combine-decryptions", status_code=200)
async def combine_decryptions(short_name: str, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for freezing an election
    """
    election = await get_auth_election(
        short_name=short_name,
        current_user=current_user,
        session=session,
        status=ElectionStatusEnum.decryptions_uploaded
    )

    task_params = {
        "election_uuid": election.uuid,
    }
    tasks.combine_decryptions.delay(**task_params)

    await psifos_logger.info(election_id=election.id, event=ElectionPublicEventEnum.DECRYPTIONS_COMBINED)
    return {
        "message": "Se han combinado las desencriptaciones parciales y el resultado ha sido calculado"
    }


@api_router.get("/{short_name}/get-trustees", status_code=200, response_model=list[schemas.TrusteeOut])
async def get_trustees(short_name: str, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for get trustees
    """
    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)
    return await crud.get_trustees_by_election_id(session=session, election_id=election.id)


@api_router.post("/{short_name}/create-trustee", status_code=200)
async def create_trustee(short_name: str, trustee_in: schemas.TrusteeIn, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for create trustee
    Require a valid token to access >>> token_required
    """
    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)
    trustee_uuid = str(uuid.uuid1())
    await crud.create_trustee(
        session=session,
        election_id=election.id,
        uuid=trustee_uuid,
        trustee_id=await crud.get_next_trustee_id(session=session, election_id=election.id),
        trustee=trustee_in
    )
    await crud.update_election(
        session=session,
        election_id=election.id,
        fields={"total_trustees": election.total_trustees + 1}
    )
    await psifos_logger.info(election_id=election.id, event=ElectionPublicEventEnum.TRUSTEE_CREATED, **trustee_in.dict())
    return {"message": "The trustee was successfully created"}


@api_router.post("/{short_name}/delete-trustee/{trustee_uuid}", status_code=200)
async def delete_trustee(short_name: str, trustee_uuid: str, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for delete trustee
    """
    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)
    await crud.delete_trustee(session=session, election_id=election.id, uuid=trustee_uuid)
    await crud.update_election(
        session=session,
        election_id=election.id,
        fields={"total_trustees": election.total_trustees - 1}
    )
    return {"message": "The trustee was successfully deleted"}


# ----- Voter Routes -----

@api_router.post("/{short_name}/cast-vote", status_code=200)
async def cast_vote(request: Request, short_name: str, cast_vote: schemas.CastVoteIn, voter_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for casting a vote
    """

    voter, election = await get_auth_voter_and_election(
        session=session,
        short_name=short_name,
        voter_login_id=voter_login_id,
        status=ElectionStatusEnum.started
    )

    task_params = {
        "serialized_encrypted_vote": cast_vote.encrypted_vote,
        "cast_ip": request.client.host,
    }

    if election.private_p:
        task_params["voter_id"] = voter.id

    else:
        task_params["voter_login_id"] = voter_login_id

    # >>> Los checks de Helios podemos hacerlos con dependencias de FastAPI <<<
    # allowed, msg = psifos_utils.do_cast_vote_checks(request, election, voter)
    # if not allowed:
    #    return make_response(jsonify({"message": f"{msg}"}), 400)

    task_params["private_p"] = election.private_p
    task_params["election_uuid"] = election.uuid

    for i in range(1000):
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
async def get_trustee(trustee_uuid, session: Session | AsyncSession = Depends(get_session)):
    """
    Route for getting a trustee
    """
    try:
        return await crud.get_trustee_by_uuid(uuid=trustee_uuid)
    except:
        raise HTTPException(
            status_code=400, detail="Error al obtener el trustee")


@api_router.get("/{short_name}/trustee/{trustee_uuid}/home", status_code=200, response_model=schemas.TrusteeHome)
async def get_trustee_home(short_name: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Trustee's route for getting his home
    """
    trustee, election = await get_auth_trustee_and_election(session=session, short_name=short_name, trustee_uuid=trustee_uuid, login_id=trustee_login_id)

    return schemas.TrusteeHome(trustee=schemas.TrusteeOut.from_orm(trustee), election=schemas.ElectionOut.from_orm(election))


@api_router.get("/{short_name}/get-randomness", status_code=200)
async def get_randomness(short_name: str, _: str = Depends(AuthUser())):
    """
    Get some randomness to sprinkle into the sjcl entropy pool
    """
    return {"randomness": base64.b64encode(os.urandom(32)).decode("utf-8")}


# Routes for keygenerator trustee (Trustee Stage 1)


@api_router.get("/{short_name}/trustee/{trustee_uuid}/get-step", status_code=200)
async def get_step(short_name: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Get the step of the trustee
    """
    _, election = await get_auth_trustee_and_election(session=session, short_name=short_name, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    trustee_step = await crud.get_global_trustee_step(
        session=session,
        election_id=election.id
    )

    return {
        "message": "Step del trustee obtenido con exito!",
        "status": trustee_step,
    }


@api_router.get("/{short_name}/get-eg-params", status_code=200)
async def election_get_eg_params(short_name: str, session: Session | AsyncSession = Depends(get_session)):
    """
    Returns a JSON with the election eg_params.
    """
    try:
        election = await crud.get_election_by_short_name(session=session, short_name=short_name)
        return election.get_eg_params()

    except:
        raise HTTPException(
            status_code=400, detail="Error al obtener los parametros de la eleccion.")


@api_router.post("/{short_name}/trustee/{trustee_uuid}/upload-pk", status_code=200)
async def trustee_upload_pk(short_name: str, trustee_uuid: str, trustee_data: schemas.PublicKeyData, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Upload public key of trustee
    """
    trustee, election = await get_auth_trustee_and_election(session=session, short_name=short_name, trustee_uuid=trustee_uuid, login_id=trustee_login_id)

    public_key_and_proof = psifos_utils.from_json(trustee_data.public_key_json)

    # TODO: validate certificate
    cert = sharedpoint.Certificate(**public_key_and_proof)

    # setting trustee's certificate and pk hash.
    trustee.certificate = cert
    trustee.public_key_hash = crypto_utils.hash_b64(str(cert.signature_key))

    # as uploading the pk is the "step 0", we need to update the current_step
    await crud.update_trustee(session=session, trustee_id=trustee.id, fields={"current_step": 1})

    await psifos_logger.info(
        election_id=election.id,
        event=ElectionPublicEventEnum.PUBLIC_KEY_UPLOADED,
        trustee_login_id=trustee.trustee_login_id,
        trustee_email=trustee.email
    )

    return {"message": "The certificate of the trustee was uploaded successfully"}


@api_router.post("/{short_name}/trustee/{trustee_uuid}/step-1", status_code=200)
async def post_trustee_step_1(short_name: str, trustee_uuid: str, trustee_data: schemas.KeyGenStep1Data, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Step 1 of the keygenerator trustee
    """
    trustee, election = await get_auth_trustee_and_election(session=session, short_name=short_name, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = await crud.get_global_trustee_step(session=session, election_id=election.id)
    if global_trustee_step != 1:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 1")

    # Instantiate coefficients
    coeffs_data = psifos_utils.from_json(trustee_data.coefficients)
    coefficients = sharedpoint.ListOfCoefficients(*coeffs_data)
    # Instantiate points
    points_data = psifos_utils.from_json(trustee_data.points)
    points = [sharedpoint.Point(**params) for params in points_data]

    # TODO: perform server-side checks here!
    await crud.delete_shared_points_by_sender(session=session, sender=trustee.trustee_id)
    await crud.create_shared_points(session=session, election_id=election.id, sender=trustee.trustee_id, points=points)

    await crud.update_trustee(session=session, trustee_id=trustee.id, fields={"coefficients": coefficients, "current_step": 2})

    return {"message": "Keygenerator step 1 completed successfully"}


@api_router.get("/{short_name}/trustee/{trustee_uuid}/step-1", status_code=200)
async def get_trustee_step_1(short_name: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Step 1 of the keygenerator trustee
    """
    _, election = await get_auth_trustee_and_election(session=session, short_name=short_name, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = await crud.get_global_trustee_step(session=session, election_id=election.id)
    if global_trustee_step != 1:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 1")

    try:
        trustees = await crud.get_trustees_by_election_id(session=session, election_id=election.id)
        certificates = [
            sharedpoint.Certificate.serialize(t.certificate, to_json=False)
            for t in trustees
        ]
        assert None not in certificates

        return {
            "certificates": psifos_utils.to_json(certificates),
        }

    except:
        raise HTTPException(
            status_code=400, detail="Some trustees haven't generated their keypair")


@api_router.post("/{short_name}/trustee/{trustee_uuid}/step-2", status_code=200)
async def post_trustee_step_2(short_name: str, trustee_uuid: str, trustee_data: schemas.KeyGenStep2Data, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Step 2 of the keygenerator trustee
    """
    trustee, election = await get_auth_trustee_and_election(session=session, short_name=short_name, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = await crud.get_global_trustee_step(session=session, election_id=election.id)
    if global_trustee_step != 2:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 2")

    acks_data = psifos_utils.from_json(trustee_data.acknowledgements)
    acks = sharedpoint.ListOfSignatures(*acks_data)

    # TODO: perform server-side checks here!
    await crud.update_trustee(session=session, trustee_id=trustee.id, fields={"acknowledgements": acks, "current_step": 3})

    return {"message": "Keygenerator step 2 completed successfully"}


@api_router.get("/{short_name}/trustee/{trustee_uuid}/step-2", status_code=200)
async def get_trustee_step_2(short_name: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Step 2 of the keygenerator trustee
    """
    trustee, election = await get_auth_trustee_and_election(session=session, short_name=short_name, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = await crud.get_global_trustee_step(session=session, election_id=election.id)
    if global_trustee_step != 2:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 2")

    try:
        trustees = await crud.get_trustees_by_election_id(session=session, election_id=election.id)
        coefficients = [
            sharedpoint.ListOfCoefficients.serialize(
                t.coefficients, to_json=False)
            for t in trustees
        ]
        assert None not in coefficients

        certificates = [
            sharedpoint.Certificate.serialize(t.certificate, to_json=False)
            for t in trustees
        ]
        assert None not in certificates

        points = await crud.format_points_sent_to(
            session=session,
            election_id=election.id,
            trustee_id=trustee.trustee_id,
        )

        return {
            "certificates": psifos_utils.to_json(certificates),
            "coefficients": psifos_utils.to_json(coefficients),
            "points": psifos_utils.to_json(points),
        }

    except:
        raise HTTPException(
            status_code=400, detail="Some trustees haven't completed the step 1 of the key generator")


@api_router.post("/{short_name}/trustee/{trustee_uuid}/step-3", status_code=200)
async def post_trustee_step_3(short_name: str, trustee_uuid: str, trustee_data: schemas.KeyGenStep3Data, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Step 3 of the keygenerator trustee
    """
    trustee, election = await get_auth_trustee_and_election(session=session, short_name=short_name, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = await crud.get_global_trustee_step(session=session, election_id=election.id)
    if global_trustee_step != 3:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 3")

    pk_data = psifos_utils.from_json(trustee_data.verification_key)
    pk = elgamal.PublicKey(**pk_data)

    # TODO: perform server-side checks here!
    await crud.update_trustee(session=session, trustee_id=trustee.id, fields={"public_key": pk, "current_step": 4})

    return {"message": "Keygenerator step 3 completed successfully"}


@api_router.get("/{short_name}/trustee/{trustee_uuid}/step-3", status_code=200)
async def post_trustee_step_3(short_name: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Step 3 of the keygenerator trustee
    """
    trustee, election = await get_auth_trustee_and_election(session=session, short_name=short_name, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    global_trustee_step = await crud.get_global_trustee_step(session=session, election_id=election.id)
    if global_trustee_step != 3:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 3")

    try:
        trustees = await crud.get_trustees_by_election_id(session=session, election_id=election.id)

        coefficients = [
            sharedpoint.ListOfCoefficients.serialize(
                t.coefficients, to_json=False)
            for t in trustees
        ]
        assert None not in coefficients

        acks_trustees = [
            sharedpoint.ListOfSignatures.serialize(
                t.acknowledgements, to_json=False)
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

        points = await crud.format_points_sent_to(
            session=session,
            election_id=election.id,
            trustee_id=trustee.trustee_id,
        )

        points_sent = await crud.format_points_sent_by(
            session=session,
            election_id=election.id,
            trustee_id=trustee.trustee_id,
        )

        return {
            "certificates": psifos_utils.to_json(certificates),
            "coefficents": psifos_utils.to_json(coefficients),
            "points": psifos_utils.to_json(points),
            "acks": psifos_utils.to_json(acknowledgements),
            "points_sent": psifos_utils.to_json(points_sent),
        }

    except:
        raise HTTPException(
            status_code=400, detail="Some trustees haven't completed the step 2 of the key generator")


@api_router.get("/{short_name}/trustee/{trustee_uuid}/check-sk", status_code=200)
async def trustee_check_sk(short_name: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Trustee Stage 2
    """
    trustee, _ = await get_auth_trustee_and_election(session=session, short_name=short_name, trustee_uuid=trustee_uuid, login_id=trustee_login_id)
    return sharedpoint.Certificate.serialize(trustee.certificate, to_json=False)


@api_router.post("/{short_name}/trustee/{trustee_uuid}/decrypt-and-prove", status_code=200)
async def trustee_decrypt_and_prove(short_name: str, trustee_uuid: str, trustee_data: schemas.DecryptionIn, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Trustee Stage 3
    """
    trustee, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        trustee_uuid=trustee_uuid,
        login_id=trustee_login_id,
        status=ElectionStatusEnum.tally_computed
    )

    decryption_list = psifos_utils.from_json(trustee_data.decryptions)
    answers_decryptions: TrusteeDecryptions = TrusteeDecryptions(
        *decryption_list)

    if answers_decryptions.verify(public_key=election.public_key, encrypted_tally=election.encrypted_tally):
        trustee = await crud.update_trustee(session=session, trustee_id=trustee.id, fields={"decryptions": answers_decryptions})
        dec_num = election.decryptions_uploaded + 1
        election = await crud.update_election(session=session, election_id=election.id, fields={"decryptions_uploaded": dec_num})

        if election.decryptions_uploaded == election.total_trustees:  # TODO: Fix
            await crud.update_election(
                session=session,
                election_id=election.id,
                fields={
                    "election_status": ElectionStatusEnum.decryptions_uploaded
                }
            )
            task_params = {
                "election_uuid": election.uuid,
            }
            tasks.combine_decryptions.delay(**task_params)
            await psifos_logger.info(election_id=election.id, event=ElectionPublicEventEnum.DECRYPTIONS_COMBINED)

            return {
                "message": "Se han combinado las desencriptaciones parciales y el resultado ha sido calculado"
            }

        await psifos_logger.info(
            election_id=election.id,
            event=ElectionPublicEventEnum.DECRYPTION_RECIEVED,
            trustee_login_id=trustee.trustee_login_id,
            trustee_email=trustee.email
        )
        return {"message": "Trustee's stage 3 completed successfully"}

    else:
        raise HTTPException(
            status_code=400, detail="An error was found during the verification of the proofs")


@api_router.get("/{short_name}/trustee/{trustee_uuid}/decrypt-and-prove", status_code=200)
async def trustee_decrypt_and_prove(short_name: str, trustee_uuid: str, trustee_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Trustee Stage 3
    """
    trustee, election = await get_auth_trustee_and_election(session=session, short_name=short_name, trustee_uuid=trustee_uuid, login_id=trustee_login_id)

    trustees = await crud.get_trustees_by_election_id(session=session, election_id=election.id)
    certificates = [sharedpoint.Certificate.serialize(
        t.certificate, to_json=False) for t in trustees]
    points = await crud.format_points_sent_to(
        session=session,
        election_id=election.id,
        trustee_id=trustee.trustee_id,
    )
    return {
        "election": schemas.ElectionOut.from_orm(election),
        "trustee": schemas.TrusteeOut.from_orm(trustee),
        "certificates": psifos_utils.to_json(certificates),
        "points": psifos_utils.to_json(points),
    }


# >>> Revisar
@api_router.get("/{short_name}/questions", status_code=200, response_model=schemas.ElectionOut)
async def get_questions(short_name: str,  voter_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):
    """
    Route for get questions
    """

    _, election = await get_auth_voter_and_election(session=session, short_name=short_name, voter_login_id=voter_login_id, status="Started")

    return election


@api_router.get("/{short_name}/questions", status_code=200)
async def get_questions(short_name: str, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Admin's route for getting all the questions of a specific election
    """
    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)
    if not election.questions:
        HTTPException(status_code=400,
                      detail="The election doesn't have questions")

    return Questions.serialize(election.questions)


@api_router.get("/{short_name}/get-certificate", status_code=200)
async def get_pdf(short_name: str, voter_login_id: str = Depends(AuthUser()), session: Session | AsyncSession = Depends(get_session)):

    """
    Return the certificate of the last vote cast by the authenticated voter

    """
    election = await crud.get_election_by_short_name(session=session, short_name=short_name)
    voter = await crud.get_voter_by_login_id_and_election_id(session=session, voter_login_id=voter_login_id, election_id=election.id)
    cast_vote = await crud.get_cast_vote_by_voter_id(session=session, voter_id=voter.id)

    hash_vote = cast_vote.vote_hash

    link_ballot = APP_FRONTEND_URL + "psifos/booth/" + short_name + \
        "/public-info?hash=" + urllib.parse.quote(hash_vote)
    img = qrcode.make(link_ballot)
    buffer = BytesIO()
    img.save(buffer, "PNG")
    img_str = b64encode(buffer.getvalue()).decode('ascii')

    with open("templates/uchile-logo.jpg", "rb") as image:
        uch_str = b64encode(image.read()).decode('ascii')

    with open("templates/participa-logo.png", "rb") as image:
        par_str = b64encode(image.read()).decode('ascii')

    with open("templates/Inter-VariableFont.ttf", "rb") as font:
        font_str = b64encode(font.read()).decode('ascii')

    pdf_data = {
        "hash_vote": hash_vote,
        "election_name": election.name,
        "cast_at": cast_vote.cast_at,
        "font_str": font_str,
        "uch_str": uch_str,
        "par_str": par_str,
        "img_str": img_str,
        "link_ballot": link_ballot
    }

    pdf = templates.get_template("vote_certificate.html")
    pdf = pdf.render(**pdf_data)
    result = pdfkit.from_string(pdf, css="templates/vote_certificate.css")
    return Response(result, media_type="application/pdf")


@api_router.post("/{short_name}/count-logs", status_code=200)
async def get_count_logs_by_date(short_name: str, data: dict = {}, current_user: models.User = Depends(AuthAdmin()), session: Session | AsyncSession = Depends(get_session)):
    """
    Return the number of logs per deltaTime from the start of the election until it ends

    """

    election = await get_auth_election(short_name=short_name, current_user=current_user, session=session)

    if election.election_status == "Setting up":
        return {}

    date_init = election.voting_started_at
    date_end = election.voting_ended_at if election.voting_ended_at else psifos_utils.tz_now()
    date_end = datetime.datetime(year=date_end.year, month=date_end.month, day=date_end.day,
                                 hour=date_end.hour, minute=date_end.minute, second=date_end.second)

    delta_minutes = data.get("minutes", 60)
    type_log = data.get("type_log", None)
    count_logs = {}
    total = 0

    while date_init <= date_end:

        date_delta = date_init + timedelta(minutes=delta_minutes)
        dates = await crud.count_logs_by_date(session=session, election_id=election.id, init_date=date_init, end_date=date_delta, type_log=type_log)
        count_date = len(dates)
        total += count_date
        count_logs[str(date_init)] = count_date
        date_init = date_delta

    return {
        "count_logs": count_logs,
        "total_logs": total
    }
# <<<
