import base64
import os
import uuid
import pdfkit
import qrcode
import urllib.parse
import app.celery_worker.psifos.tasks as tasks
import datetime
import threading

from fastapi import Depends, HTTPException, APIRouter, UploadFile, Request, Response
from app.psifos.model.enums import ElectionStatusEnum, ElectionPublicEventEnum, ElectionLoginTypeEnum, TrusteeStepEnum
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.psifos.crypto.tally.common.decryption.trustee_decryption import (
    TrusteeDecryptionsManager,
    TrusteeDecryptionsGroup,
)
from app.psifos.crypto.tally.tally import TallyWrapper

from app.config import APP_FRONTEND_URL

from app.psifos.model import models
from app.psifos.model.cruds import crud
from app.psifos.model.cruds import crypto_crud
from app.psifos.model.cruds import results as results_crud
from app.psifos.model.schemas import schemas
from app.psifos.model.schemas import crypto_schemas
from app.psifos.model.cruds import questions as questions_crud
from app.dependencies import get_session
from app.psifos.crypto import elgamal, sharedpoint
from app.psifos.crypto import utils as crypto_utils
from app.psifos import utils as psifos_utils
from app.psifos_auth.auth_bearer import AuthAdmin
from app.psifos_auth.utils import (
    get_auth_election,
    get_auth_trustee_and_election,
    get_auth_voter_and_election,
)
from app.psifos_auth.auth_service_check import AuthUser
from app.psifos_auth.redis_store import get_session_data
from sqlalchemy.ext.asyncio import AsyncSession

from datetime import timedelta

from app.logger import psifos_logger, logger
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
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Admin's route for creating an election
    """
    election_exists = (
        await crud.get_election_by_short_name(
            short_name=election_in.short_name, session=session
        )
        is not None
    )
    if election_exists:
        raise HTTPException(status_code=404, detail="The election already exists.")

    await crud.create_election(
        session=session,
        election=election_in,
        admin_id=current_user.get_id(),
    )
    return {"message": "Elección creada con exito!"}


@api_router.get("/delete-election/{short_name}", status_code=200)
async def delete_election(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Admin's route for delete a election by uuid
    """
    try:
        election = await get_auth_election(
            short_name=short_name, current_user=current_user, session=session
        )
        await crud.delete_election(session=session, election_id=election.id)
        await crypto_crud.delete_unused_public_keys(session=session)
        return {"message": "election delete"}

    except:
        raise HTTPException(status_code=404, detail="error in delete election")

@api_router.get(
    "/get-election/{short_name}", response_model=schemas.ElectionOut, status_code=200
)
async def get_election(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Admin's route for getting a specific election by uuid
    """
    result = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )
    return result

@api_router.get(
    "/get-elections", response_model=list[schemas.SimpleElection], status_code=200
)
async def get_elections(
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Admin's route for getting all elections administered by him
    """

    elections = await crud.get_elections_by_user(
        session=session, admin_id=current_user.get_id()
    )

    return [election for election in elections]


@api_router.post("/edit-election/{short_name}", status_code=201)
async def edit_election(
    short_name: str,
    election_in: schemas.ElectionIn,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Admin's route for editing an election
    """
    election_exist = (
        await crud.get_election_by_short_name(
            session=session, short_name=election_in.short_name
        )
        is not None
    )
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )

    if election_exist and election.short_name != election_in.short_name:
        raise HTTPException(status_code=404, detail="The election already exists.")

    await crud.edit_election(
        session=session, election_id=election.id, election=election_in
    )
    return {"message": "Election edited successfully!"}


@api_router.post("/create-questions/{short_name}", status_code=200)
async def create_questions(
    short_name: str,
    data_questions: dict,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Admin's route for creating questions for an election
    """
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )
    questions = await crud.get_questions_by_election_id(session=session, election_id=election.id)
    total_questions = len(questions) if questions else 0
    for index, question in enumerate(data_questions["question"]):
        question["index"] = index + 1

        if await questions_crud.get_question_by_index(
            session=session, election_id=election.id, index=question["index"]
        ):
            await questions_crud.edit_question(
                session=session,
                election_id=election.id,
                question_id=question["index"],
                question=question,
            )
        else:
            await questions_crud.create_question(
                session=session, election_id=election.id, question=question
            )
    
    if total_questions > len(data_questions["question"]):
        for index in range(len(data_questions["question"]) + 1, total_questions + 1):
            await questions_crud.delete_questions_by_election_id_index(
                session=session, election_id=election.id, index=index
            )

    return {"message": "Preguntas creadas con exito!"}


@api_router.post("/{short_name}/upload-voters", status_code=200)
async def upload_voters(
    short_name: str,
    file: UploadFile,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Admin's route for uploading the voters of an election
    """
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )

    voter_file_content = file.file.read().decode("utf-8")
    task_params = {
        "election_id": election.id,
        "voter_file_content": voter_file_content,
    }
    task = tasks.upload_voters.delay(**task_params)
    status, voter_counter, total_voters = task.get()

    if status:
        await psifos_logger.info(
            election_id=election.id, event=ElectionPublicEventEnum.VOTER_FILE_UPLOADED
        )
        return {
            "message": f"[{voter_counter}/{total_voters}] voters were successfully uploaded"
        }
    else:
        raise HTTPException(status_code=400, detail="Failed to upload the voters")


@api_router.post(
    "/{short_name}/get-voters", response_model=list[schemas.VoterOut], status_code=200
)
async def get_voters(
    short_name: str,
    data: dict = {},
    current_user: models.User = Depends(AuthAdmin()),
    session: Session = Depends(get_session),
):
    """
    Route for get voters
    """

    page = data.get("page", 0)
    page_size = data.get("page_size", None)
    page = page_size * page if page_size else None

    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )
    return await crud.get_voters_by_election_id(
        session=session, election_id=election.id, page=page, page_size=page_size
    )


@api_router.post(
    "/{short_name}/voters/edit",
    response_model=schemas.VoterOut,
    status_code=200,
)
async def edit_voter(
    short_name: str,
    fields_voter: dict,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for get a voter
    """
    election_params = [models.Election.id]
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session, election_params=election_params
    )
    username = fields_voter.get("username")
    old_username = fields_voter.pop("old_username")
    username_election_id = f"{username}_{election.id}"
    fields_voter["username_election_id"] = username_election_id
    return await crud.edit_voter(
        old_username=old_username,
        new_username=username,
        session=session,
        election_id=election.id,
        fields=fields_voter,
    )

@api_router.post("/{short_name}/delete-voters", status_code=200)
async def delete_voters(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for delete voters
    """
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )
    await crud.delete_election_voters(session=session, election_id=election.id)
    await psifos_logger.warning(
        election_id=election.id, event=ElectionPublicEventEnum.ELECTORAL_ROLL_MODIFIED
    )


@api_router.post("/{short_name}/voter/{username}/delete")
async def delete_voter(
    short_name: str,
    username: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for delete a voter
    """
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )
    voter = await crud.get_voter_by_login_id_and_election_id(
        session=session, username=username, election_id=election.id
    )
    voter_cast_votes = await crud.get_cast_vote_by_voter_id(
        session=session, voter_id=voter.id
    )
    if voter_cast_votes:
        raise HTTPException(
            status_code=400, detail="The voter has already cast votes"
        )
    await crud.delete_election_voter(
        session=session, election_id=election.id, username=username
    )
    await psifos_logger.warning(
        election_id=election.id,
        event=ElectionPublicEventEnum.ELECTORAL_ROLL_MODIFIED,
        username=username,
    )

@api_router.post("/{short_name}/get-weights", status_code=200)
async def get_weights(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    data: dict = {},
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for init weights
    """
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )
    voters = await crud.get_voters_by_election_id(
        session=session, election_id=election.id
    )
    type_weight = data.get("type_weight", "init")

    voters = [v for v in voters if await v.has_valid_vote(session=session)]
    voters_by_weight = {}
    normalized_weights = {}

    for v in voters:
        voter_weight = v.weight_init if type_weight == "init" else v.weight_end
        v_w = voter_weight / election.max_weight
        v_g = v.group
        normalized_weights.setdefault(v_g, []).append(v_w)
        voters_by_weight[v_w] = voters_by_weight.get(v_w, 0) + 1

    voters_by_weight_grouped = [
        {"group": group, "weights": {str(w): weights_group.count(w) for w in set(weights_group)}}
        for group, weights_group in normalized_weights.items()
    ]

    weight = {
        "voters_by_weight": voters_by_weight,
        "voters_by_weight_grouped": voters_by_weight_grouped
    }

    return weight

@api_router.post("/{short_name}/ready-key-generation", status_code=200)
async def ready_key_generation(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for ready key generation
    """
    election = await get_auth_election(
        short_name=short_name, 
        current_user=current_user, 
        session=session,
        status=ElectionStatusEnum.setting_up,
        simple=False
    )
    status, message = election.ready_key_generation() 
    if not status:
        raise HTTPException(status_code=400, detail=message)
    
    if election.has_psifos_trustees:
        pk_id = await election.generate_trustee(session=session)
        election = await crud.update_election(
            session=session,
            election_id=election.id,
            fields={
                "public_key_id": pk_id,
                "status": ElectionStatusEnum.ready_opening
            },
        )
        
    else:
        election = await crud.update_election(
            session=session, election_id=election.id, fields={"status": ElectionStatusEnum.ready_key_generation}
        )
        trustees = await crud.get_trustees_by_election_id(session=session, election_id=election.id)
        for trustee in trustees:
            await crud.update_trustee_crypto(
                session=session,
                trustee_id=trustee.id,
                election_id=election.id,
                fields={"current_step": TrusteeStepEnum.secret_key_step}
            )

    await psifos_logger.info(
        election_id=election.id, event=ElectionPublicEventEnum.KEY_GENERATION_READY
    )
    return {"message": message, "status": election.status}

@api_router.post("/{short_name}/back-to-setting-up", status_code=200)
async def back_to_setting_up(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for back to setting up
    """
    election = await get_auth_election(
        short_name=short_name, 
        current_user=current_user, 
        session=session,
        status=ElectionStatusEnum.ready_key_generation
    )
    await crud.update_election(
        session=session, election_id=election.id, fields={"status": ElectionStatusEnum.setting_up}
    )
    trustees = await crud.get_trustees_by_election_id(session=session, election_id=election.id)
    for trustee in trustees:
        await crud.update_trustee_crypto(
            session=session,
            trustee_id=trustee.id,
            election_id=election.id,
            fields={"current_step": TrusteeStepEnum.config_step}
        )

    await psifos_logger.info(
        election_id=election.id, event=ElectionPublicEventEnum.BACK_TO_SETTING_UP
    )
    return {"message": "The election was successfully set up"}

@api_router.post("/{short_name}/ready-opening", status_code=200)
async def ready_opening(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for ready opening
    """
    election = await get_auth_election(
        short_name=short_name, 
        current_user=current_user, 
        session=session,
        status=ElectionStatusEnum.ready_key_generation
    )
    status, message = election.ready_opening()
    if not status:
        raise HTTPException(status_code=400, detail=message)
    
    await crud.update_election(
        session=session, election_id=election.id, fields={"status": ElectionStatusEnum.ready_opening}
    )

    await psifos_logger.info(
        election_id=election.id, event=ElectionPublicEventEnum.OPENING_READY
    )
    return {"message": message}

@api_router.post("/{short_name}/start-election", status_code=200)
async def start_election(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for starting an election, once it happens the election
    gets "frozen" which means it shouldn't be modified from now on.
    """
    election = await get_auth_election(
        short_name=short_name,
        current_user=current_user,
        session=session,
        status=ElectionStatusEnum.ready_opening,
        simple=False,
    )
    await crud.update_election(
        session=session, election_id=election.id, fields=await election.start(session=session)
    )

    await psifos_logger.info(
        election_id=election.id, event=ElectionPublicEventEnum.VOTING_STARTED
    )

    return {"message": "The election was succesfully started"}


@api_router.post("/{short_name}/end-election", status_code=200)
async def end_election(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for ending an election, once it happens no voter
    should be able to cast a vote.
    """
    election = await get_auth_election(
        short_name=short_name,
        current_user=current_user,
        session=session,
        simple=True,
        status=ElectionStatusEnum.started,
    )

    not_null_voters = await crud.get_count_valid_cast_votes_by_election_id(
        session=session, election_id=election.id
    )

    if not_null_voters < 1:
        groups = await crud.get_groups_by_election_id(session=session, election_id=election.id)
        questions = await questions_crud.get_questions_by_election_id(
            session=session, election_id=election.id
        )
        await results_crud.create_result(
            session=session,
            election_id=election.id,
            result=election.end_without_votes(groups=groups, questions=questions),
        )
        await crud.update_election(
            session=session,
            election_id=election.id,
            fields={"status": ElectionStatusEnum.decryptions_combined},
        )
        await psifos_logger.info(
            election_id=election.id, event=ElectionPublicEventEnum.VOTING_STOPPED
        )
        return {"message": "The election was succesfully ended"}

    await crud.update_election(
        session=session, election_id=election.id, fields=election.end()
    )

    await psifos_logger.info(
        election_id=election.id, event=ElectionPublicEventEnum.VOTING_STOPPED
    )

    return {"message": "The election was succesfully ended"}


@api_router.post("/{short_name}/compute-tally", status_code=200)
async def compute_tally(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for freezing an election
    """

    try:
        election = await get_auth_election(
            short_name=short_name,
            current_user=current_user,
            session=session,
            status=ElectionStatusEnum.ended,
        )
        await crud.update_election(
            session=session,
            election_id=election.id,
            fields={
                "status": ElectionStatusEnum.computing_tally,
            },
        )

        pk = election.public_key

        task_params = {
            "short_name": election.short_name,
            "public_key": pk.to_dict(),
        }

        tasks.compute_tally.delay(**task_params)

        await psifos_logger.info(
            election_id=election.id, event=ElectionPublicEventEnum.TALLY_COMPUTED
        )

        return {"message": "The encrypted tally was succesfully computed"}

    except Exception as e:
        await crud.update_election(
            session=session,
            election_id=election.id,
            fields={
                "status": ElectionStatusEnum.ended,
            },
        )
        return {"message": "An error has occurred while computing the tally"}


@api_router.post("/{short_name}/combine-decryptions", status_code=200)
async def combine_decryptions(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for freezing an election
    """
    election = await get_auth_election(
        short_name=short_name,
        current_user=current_user,
        session=session,
    )

    trustees_crypto = await crud.get_trustees_crypto_by_election_id(
        session=session, election_id=election.id
    )

    decryptions_uploaded = filter(lambda t: t.current_step == TrusteeStepEnum.decryptions_sent, trustees_crypto)
    total_decryptions_uploaded = len(list(decryptions_uploaded))

    total_trustees = await crud.get_total_trustees_by_election_id(
        session=session, election_id=election.id
    )

    if total_decryptions_uploaded < (total_trustees // 2) + 1:
        return HTTPException(status_code=400, detail="Insuficientes desencriptaciones")

    task_params = {
        "short_name": election.short_name,
    }
    tasks.combine_decryptions.delay(**task_params)

    await psifos_logger.info(
        election_id=election.id, event=ElectionPublicEventEnum.DECRYPTIONS_COMBINED
    )
    return {
        "message": "Se han combinado las desencriptaciones parciales y el resultado ha sido calculado"
    }


@api_router.post("/{short_name}/results-release", status_code=200)
async def results_release(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for release results
    """
    election = await get_auth_election(
        short_name=short_name,
        current_user=current_user,
        session=session,
        status=ElectionStatusEnum.decryptions_combined,
    )
    await crud.update_election(
        session=session, election_id=election.id, fields=election.results_released()
    )

    await psifos_logger.info(
        election_id=election.id, event=ElectionPublicEventEnum.RESULTS_RELEASED
    )

    return {"message": "The election has released the results"}


@api_router.get(
    "/{short_name}/get-trustees",
    status_code=200,
)
async def get_trustees(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for get trustees
    """

    election_params = [
        models.Election.id,
    ]
    trustee_params = [
        models.TrusteeCrypto.current_step,
        models.TrusteeCrypto.public_key_hash,
        models.Trustee.name,
        models.Trustee.username,
        models.Trustee.email
    ]
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session, election_params=election_params
    )
    return await crud.get_trustees_params_by_election_id(
        session=session, election_id=election.id, params=trustee_params
    )

@api_router.post("/{short_name}/create-trustee", status_code=200)
async def create_trustee(
    short_name: str,
    trustee_in: schemas.TrusteeIn,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for create trustee
    Require a valid token to access >>> token_required
    """
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )
    trustee = await crud.get_trustee_by_username(
        session=session, username=trustee_in.username
    )
    if not trustee:
        trustee = await crud.create_trustee(
            session=session,
            trustee=trustee_in,
        )
    await crud.create_trustee_crypto(
        session=session,
        election_id=election.id,
        trustee_id=trustee.id,
        trustee_election_id=await crud.get_next_trustee_id(
            session=session, election_id=election.id
        ),
    )
    
    await psifos_logger.info(
        election_id=election.id,
        event=ElectionPublicEventEnum.TRUSTEE_CREATED,
        **trustee_in.dict(),
    )
    return {"message": "The trustee was successfully created"}

@api_router.get("/{short_name}/trustee/{trustee_uuid}/get-decryptions", status_code=200)
async def get_decryptions(
    short_name: str,
    trustee_uuid: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for get decryptions
    """
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )
    trustee = await crud.get_trustee_by_uuid(session=session, uuid=trustee_uuid)
    trustee_crypto = await crud.get_trustee_crypto_by_trustee_id_election_id(
        session=session, trustee_id=trustee.id, election_id=election.id
    )
    decryptions = await crud.get_decryptions_by_trustee_id(
        session=session, trustee_crypto_id=trustee_crypto.id
    )
    return decryptions


@api_router.post("/{short_name}/delete-trustee/{trustee_username}", status_code=200)
async def delete_trustee(
    short_name: str,
    trustee_username: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for delete trustee
    """
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )

    trustee = await crud.get_trustee_by_username(session=session, username=trustee_username)
    trustee_crypto = await crud.get_trustee_crypto_by_trustee_id_election_id(
        session=session, trustee_id=trustee.id, election_id=election.id
    )

    # Existe una crypto asociada a este custodio para esta elección
    if trustee_crypto:
        await crud.delete_trustee_crypto(session=session, trustee_id=trustee.id, election_id=election.id)
        await crypto_crud.delete_unused_public_keys(session=session)
        cryptos_election = await crud.get_trustees_crypto_by_election_id(
            session=session, election_id=election.id
        )

        # Debemos actualizar el id de los otros custodios
        for index, crypto in enumerate(cryptos_election):
            await crud.update_trustee_crypto(
                session=session,
                trustee_id=crypto.trustee_id,
                election_id=election.id,
                fields={"trustee_election_id": index + 1},
            )
            
    other_crypto = await crud.get_trustees_crypto_by_trustee_id(
        session=session, trustee_id=trustee.id
    )

    # Si el custodio existe en otra elección, no lo eliminamos
    if len(other_crypto) == 0:
        await crud.delete_trustee(
            session=session, uuid=trustee_uuid
        )

        await crud.update_election(
            session=session,
            election_id=election.id,
            fields={"total_trustees": election.total_trustees - 1},
        )

    return {"message": "The trustee was successfully deleted"}
    

# ----- Voter Routes -----


@api_router.post("/{short_name}/cast-vote", status_code=200)
async def cast_vote(
    request: Request,
    short_name: str,
    cast_vote: schemas.CastVoteIn,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for casting a vote
    """
    query_params = [
        models.Election.voters_login_type,
        models.Election.short_name,
        models.Election.questions
    ]

    voter, election = await get_auth_voter_and_election(
        session=session,
        short_name=short_name,
        username=username,
        status=ElectionStatusEnum.started,
        election_params=query_params
    )
    task_params = {
        "serialized_encrypted_vote": cast_vote.encrypted_vote,
    }
    if election.voters_login_type == ElectionLoginTypeEnum.close_p:
        task_params["voter_id"] = voter.id

    else:
        task_params["username"] = username

    # >>> Los checks de Helios podemos hacerlos con dependencias de FastAPI <<<
    # allowed, msg = psifos_utils.do_cast_vote_checks(request, election, voter)
    # if not allowed:
    #    return make_response(jsonify({"message": f"{msg}"}), 400)
    task_params["voters_login_type"] = election.voters_login_type
    task_params["election_short_name"] = election.short_name
    task = tasks.process_cast_vote.delay(**task_params)
    verified, vote_fingerprint = task.get()
    if verified:
        logger.log("PSIFOS", "%s - Valid Cast Vote: %s (%s)" % (request.client.host, username, election.short_name))
        return {
            "message": "Encrypted vote received succesfully",
            "verified": verified,
            "encrypted_ballot_hash": vote_fingerprint,
        }
    else:
        logger.error("%s - Invalid Cast Vote: %s (%s)" % (request.client.host, username, election.short_name))
        return {"message": "Invalid encrypted vote", "verified": verified}


# ----- Trustee Routes -----


@api_router.get(
    "/{trustee_uuid}/get-trustee", status_code=200, response_model=schemas.TrusteeOut
)
async def get_trustee(
    trustee_uuid, session: Session | AsyncSession = Depends(get_session)
):
    """
    Route for getting a trustee
    """
    try:
        return await crud.get_trustee_by_uuid(uuid=trustee_uuid)
    except:
        raise HTTPException(status_code=400, detail="Error al obtener el trustee")


@api_router.get(
    "/trustee/panel",
    status_code=200,
    response_model=schemas.TrusteePanel,
)
async def get_trustee_panel(
    request: Request,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Trustee's route for getting his home
    """

    session_id = request.session.get("session_id")
    session_data = await get_session_data(session_id)
    username = session_data.get("user")
    if not username:
        raise HTTPException(status_code=400, detail="Custodio sin elecciones")
    trustee = await crud.get_trustee_by_username(session=session, username=username)
    if trustee.username != username:
        raise HTTPException(status_code=400, detail="No autorizado")

    trustee_crypto = await crud.get_trustees_crypto_by_trustee_id(
        session=session, trustee_id=trustee.id
    )
    final = []
    for t_c in trustee_crypto:
        election = await crud.get_election_by_id(session=session, election_id=t_c.election_id)
        crypto = schemas.TrusteeCryptoPanel.from_orm(t_c)
        crypto.election_short_name = election.short_name
        crypto.election_status = election.status
        final.append(
            crypto
        )

    return schemas.TrusteePanel(
        trustee=trustee,
        trustee_crypto=final
    )
    

@api_router.get("/{short_name}/trustee/crypto", status_code=200)
async def get_trustee_crypto(
    request: Request,
    short_name: str,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Trustee's route for getting his crypto data
    """
    trustee, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
    )

    trustee_crypto = await crud.get_trustee_crypto_by_trustee_id_election_id(
        session=session, trustee_id=trustee.id, election_id=election.id
    )
    return {
        "trustee": schemas.TrusteeBase.from_orm(trustee),
        "trustee_crypto": schemas.TrusteeCryptoBase.from_orm(trustee_crypto),
        "election": schemas.ElectionOut.from_orm(election),
    }



    decryptions = await crud.get_decryptions_by_trustee_id(
        session=session, trustee_id=trustee.id
    )

    return schemas.TrusteeHome(
        trustee=schemas.TrusteeOut.from_orm(trustee),
        election=schemas.ElectionOut.from_orm(election),
        decryptions=decryptions
    )

@api_router.get("/{short_name}/get-randomness", status_code=200)
async def get_randomness(short_name: str, _: str = Depends(AuthUser())):
    """
    Get some randomness to sprinkle into the sjcl entropy pool
    """
    return {"randomness": base64.b64encode(os.urandom(32)).decode("utf-8")}


# Routes for keygenerator trustee (Trustee Stage 1)


@api_router.get("/{short_name}/trustee/get-step", status_code=200)
async def get_step(
    request: Request,
    short_name: str,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Get the step of the trustee
    """
    _, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
    )
    trustee_step = await crud.get_global_trustee_step(
        session=session, election_id=election.id
    )

    return {
        "message": "Step del trustee obtenido con exito!",
        "status": trustee_step.value,
    }


@api_router.get("/{short_name}/get-eg-params", status_code=200)
async def election_get_eg_params(
    short_name: str, session: Session | AsyncSession = Depends(get_session)
):
    """
    Returns a JSON with the election eg_params.
    """
    try:
        election = await crud.get_election_by_short_name(
            session=session, short_name=short_name
        )
        # total_trustees = await crud.get_total_trustees_by_election_id(
        #     session=session, election_id=election.id
        # )
        # return election.get_eg_params(total_trustees=total_trustees)        
        return election.get_eg_params()

    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=400, detail="Error al obtener los parametros de la eleccion."
        )


@api_router.post("/{short_name}/trustee/upload-pk", status_code=200)
async def trustee_upload_pk(
    request: Request,
    short_name: str,
    trustee_data: schemas.PublicKeyData,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Upload public key of trustee
    """
    trustee, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
        status=ElectionStatusEnum.ready_key_generation
    )

    trustee_crypto = await crud.get_trustee_crypto_by_trustee_id_election_id(
        session=session, trustee_id=trustee.id, election_id=election.id
    )
    if trustee_crypto.current_step != TrusteeStepEnum.secret_key_step:
        raise HTTPException(
            status_code=400, detail="The trustee's current step is not 0"
        )

    public_key_and_proof = psifos_utils.from_json(trustee_data.public_key_json)

    # TODO: validate certificate
    cert = sharedpoint.Certificate(**public_key_and_proof)

    # setting trustee's certificate and pk hash.
    trustee_crypto.certificate = cert
    trustee_crypto.public_key_hash = crypto_utils.hash_b64(str(cert.signature_key))

    # as uploading the pk is the "step 0", we need to update the current_step
    await crud.update_trustee_crypto(
        session=session, trustee_id=trustee.id, election_id=election.id, fields={"current_step": TrusteeStepEnum.certificates_step}
    )

    await psifos_logger.info(
        election_id=election.id,
        event=ElectionPublicEventEnum.PUBLIC_KEY_UPLOADED,
        username=trustee.username,
        trustee_email=trustee.email,
    )

    return {"message": "The certificate of the trustee was uploaded successfully"}


@api_router.post("/{short_name}/trustee/step-1", status_code=200)
async def post_trustee_step_1(
    request: Request,
    short_name: str,
    trustee_data: schemas.KeyGenStep1Data,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Step 1 of the keygenerator trustee
    """
    trustee, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
        status=ElectionStatusEnum.ready_key_generation
    )

    trustee_crypto = await crud.get_trustee_crypto_by_trustee_id_election_id(
        session=session, trustee_id=trustee.id, election_id=election.id
    )

    global_trustee_step = await crud.get_global_trustee_step(
        session=session, election_id=election.id
    )
    if global_trustee_step != TrusteeStepEnum.certificates_step:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 1"
        )

    # Instantiate coefficients
    coeffs_data = psifos_utils.from_json(trustee_data.coefficients)
    coefficients = sharedpoint.ListOfCoefficients(*coeffs_data)
    # Instantiate points
    points_data = psifos_utils.from_json(trustee_data.points)
    points = [sharedpoint.Point(**params) for params in points_data]

    # TODO: perform server-side checks here!
    await crud.delete_shared_points_by_sender_and_election_id(
        session=session, sender=trustee_crypto.trustee_election_id, election_id=election.id
    )
    await crud.create_shared_points(
        session=session,
        election_id=election.id,
        sender=trustee_crypto.trustee_election_id,
        points=points,
    )

    await crud.update_trustee_crypto(
        session=session,
        trustee_id=trustee.id,
        election_id=election.id,
        fields={"coefficients": coefficients, "current_step": TrusteeStepEnum.coefficients_step},
    )

    return {"message": "Keygenerator step 1 completed successfully"}


@api_router.get("/{short_name}/trustee/step-1", status_code=200)
async def get_trustee_step_1(
    request: Request,
    short_name: str,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Step 1 of the keygenerator trustee
    """
    _, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
        status=ElectionStatusEnum.ready_key_generation
    )
    global_trustee_step = await crud.get_global_trustee_step(
        session=session, election_id=election.id
    )
    if global_trustee_step != TrusteeStepEnum.certificates_step:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 1"
        )

    try:
        trustees = await crud.get_trustees_crypto_by_election_id(
            session=session, election_id=election.id
        )
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
            status_code=400, detail="Some trustees haven't generated their keypair"
        )


@api_router.post("/{short_name}/trustee/step-2", status_code=200)
async def post_trustee_step_2(
    request: Request,
    short_name: str,
    trustee_data: schemas.KeyGenStep2Data,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Step 2 of the keygenerator trustee
    """
    trustee, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
        status=ElectionStatusEnum.ready_key_generation
    )
    global_trustee_step = await crud.get_global_trustee_step(
        session=session, election_id=election.id
    )
    if global_trustee_step != TrusteeStepEnum.coefficients_step:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 2"
        )

    acks_data = psifos_utils.from_json(trustee_data.acknowledgements)
    acks = sharedpoint.ListOfSignatures(*acks_data)

    # TODO: perform server-side checks here!
    await crud.update_trustee_crypto(
        session=session,
        trustee_id=trustee.id,
        election_id=election.id,
        fields={"acknowledgements": acks, "current_step": TrusteeStepEnum.points_step},
    )

    return {"message": "Keygenerator step 2 completed successfully"}


@api_router.get("/{short_name}/trustee/step-2", status_code=200)
async def get_trustee_step_2(
    request: Request,
    short_name: str,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Step 2 of the keygenerator trustee
    """
    trustee, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
        status=ElectionStatusEnum.ready_key_generation
    )

    trustee_crypto = await crud.get_trustee_crypto_by_trustee_id_election_id(
        session=session, trustee_id=trustee.id, election_id=election.id
    )

    global_trustee_step = await crud.get_global_trustee_step(
        session=session, election_id=election.id
    )
    if global_trustee_step != TrusteeStepEnum.coefficients_step:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 2"
        )

    try:
        trustees = await crud.get_trustees_crypto_by_election_id(
            session=session, election_id=election.id
        )
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

        points = await crud.format_points_sent_to(
            session=session,
            election_id=election.id,
            trustee_id=trustee_crypto.trustee_election_id,
        )

        return {
            "certificates": psifos_utils.to_json(certificates),
            "coefficients": psifos_utils.to_json(coefficients),
            "points": psifos_utils.to_json(points),
        }

    except:
        raise HTTPException(
            status_code=400,
            detail="Some trustees haven't completed the step 1 of the key generator",
        )


@api_router.post("/{short_name}/trustee/step-3", status_code=200)
async def post_trustee_step_3(
    request: Request,
    short_name: str,
    trustee_data: schemas.KeyGenStep3Data,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Step 3 of the keygenerator trustee
    """
    trustee, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
        status=ElectionStatusEnum.ready_key_generation
    )
    global_trustee_step = await crud.get_global_trustee_step(
        session=session, election_id=election.id
    )
    if global_trustee_step != TrusteeStepEnum.points_step:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 3"
        )

    pk_data = psifos_utils.from_json(trustee_data.verification_key)

    # TODO: perform server-side checks here!
    public_key = await crypto_crud.create_public_key(
        session=session,
        public_key=pk_data,
    )
    await crud.update_trustee_crypto(
        session=session,
        trustee_id=trustee.id,
        election_id=election.id,
        fields={"current_step": TrusteeStepEnum.waiting_decryptions, "public_key_id": public_key.id},
    )

    global_trustee_step = await crud.get_global_trustee_step(
        session=session, election_id=election.id
    )

    if global_trustee_step == TrusteeStepEnum.waiting_decryptions:
        await crud.update_election(
            session=session, election_id=election.id, fields={"status": ElectionStatusEnum.ready_opening}
        )


    logger.log("PSIFOS", "%s - Valid Key Generation: %s (%s)" % (request.client.host, username, short_name))
    return {"message": "Keygenerator step 3 completed successfully"}


@api_router.get("/{short_name}/trustee/step-3", status_code=200)
async def post_trustee_step_3(
    request: Request,
    short_name: str,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Step 3 of the keygenerator trustee
    """
    trustee, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
        status=ElectionStatusEnum.ready_key_generation
    )

    trustee_crypto = await crud.get_trustee_crypto_by_trustee_id_election_id(
        session=session, trustee_id=trustee.id, election_id=election.id
    )

    global_trustee_step = await crud.get_global_trustee_step(
        session=session, election_id=election.id
    )
    if global_trustee_step != TrusteeStepEnum.points_step:
        raise HTTPException(
            status_code=400, detail="The election's global trustee step is not 3"
        )

    try:
        trustees = await crud.get_trustees_crypto_by_election_id(
            session=session, election_id=election.id
        )

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
        ack_indx = trustee_crypto.trustee_election_id - 1
        acknowledgements = [acks[ack_indx] for acks in acks_trustees]

        certificates = [
            sharedpoint.Certificate.serialize(t.certificate, to_json=False)
            for t in trustees
        ]
        assert None not in certificates

        points = await crud.format_points_sent_to(
            session=session,
            election_id=election.id,
            trustee_id=trustee_crypto.trustee_election_id,
        )

        points_sent = await crud.format_points_sent_by(
            session=session,
            election_id=election.id,
            trustee_id=trustee_crypto.trustee_election_id,
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
            status_code=400,
            detail="Some trustees haven't completed the step 2 of the key generator",
        )


@api_router.get("/{short_name}/trustee/check-sk", status_code=200)
async def trustee_check_sk(
    request: Request,
    short_name: str,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Trustee Stage 2
    """
    trustee, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
    )

    trustee_crypto = await crud.get_trustee_crypto_by_trustee_id_election_id(
        session=session, trustee_id=trustee.id, election_id=election.id
    )

    return sharedpoint.Certificate.serialize(trustee_crypto.certificate, to_json=False)


# Crear un bloqueo global
dec_num_lock = threading.Lock()


@api_router.post(
    "/{short_name}/trustee/decrypt-and-prove", status_code=200
)
async def trustee_decrypt_and_prove(
    request: Request,
    short_name: str,
    trustee_data: list[schemas.DecryptionIn],
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Trustee Stage 3
    """
    trustee, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
        status=ElectionStatusEnum.tally_computed,
    )

    trustee_crypto = await crud.get_trustee_crypto_by_trustee_id_election_id(
        session=session, trustee_id=trustee.id, election_id=election.id
    )
    public_key = await crypto_crud.get_public_key(
        session=session, id=trustee_crypto.public_key_id
    )

    decryption_list = psifos_utils.from_json(trustee_data)
    answers_decryptions_list = []
    for decryption in decryption_list:
        answers_decryptions: TrusteeDecryptionsGroup = TrusteeDecryptionsGroup(
            decryption.group, decryption.decryptions
        )
        encrypted_tally_group = await crud.get_tally_by_group(session=session, election_id=election.id, group=decryption.group)
        if answers_decryptions.decryptions.verify(
            public_key=public_key,
            encrypted_tally=encrypted_tally_group,
        ):
            for q_num, dec in enumerate(answers_decryptions.decryptions.instances):

                question = await crud.get_question_by_election_id_and_index(
                    session=session, election_id=election.id, index=q_num + 1
                )
                
                await crud.create_decryption(
                    session=session,
                    trustee_crypto_id=trustee_crypto.id,
                    group=decryption.group,
                    question=question,
                    decryption=dec,
                )
            answers_decryptions_list.append(answers_decryptions)

        else:
            logger.error("%s - Invalid Decryptions Received: %s (%s)" % (request.client.host, trustee.username, short_name))
            raise HTTPException(
                status_code=400,
                detail="An error was found during the verification of the proofs",
            )
    decryptions = TrusteeDecryptionsManager(*answers_decryptions_list)
    # Zona critica, solo un custodio puede entrar y cambiar las desencriptaciones
    with dec_num_lock:
        # Sacamos la elección denuevo por si ha recibido algún cambio de otro custodio
        election = await crud.get_election_by_short_name(
            session=session, short_name=short_name
        )
        trustee_crypto = await crud.update_trustee_crypto(
            session=session,
            trustee_id=trustee.id,
            election_id=election.id,
            fields={"current_step": TrusteeStepEnum.decryptions_sent},
        )
        dec_num = election.decryptions_uploaded + 1
        logger.log("PSIFOS", "%s - Valid Decryptions Received: %s (%s)" % (request.client.host, trustee.username, short_name))
        await psifos_logger.info(
            election_id=election.id,
            event=ElectionPublicEventEnum.DECRYPTION_RECIEVED,
            name=trustee.name,
            username=trustee.username,
            trustee_email=trustee.email,
        )

    if election.decryptions_uploaded == election.total_trustees:  # TODO: Fix
        await crud.update_election(
            session=session,
            election_id=election.id,
            fields={"status": ElectionStatusEnum.decryptions_uploaded},
        )
        task_params = {
            "short_name": election.short_name,
        }
        tasks.combine_decryptions.delay(**task_params)
        await psifos_logger.info(
            election_id=election.id,
            event=ElectionPublicEventEnum.DECRYPTIONS_COMBINED,
        )

        return {
            "message": "Se han combinado las desencriptaciones parciales y el resultado ha sido calculado"
        }

    return {"message": "Trustee's stage 3 completed successfully"}


@api_router.get(
    "/{short_name}/trustee/decrypt-and-prove", status_code=200
)
async def trustee_decrypt_and_prove(
    request: Request,
    short_name: str,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Trustee Stage 3
    """ 
    trustee, election = await get_auth_trustee_and_election(
        session=session,
        short_name=short_name,
        username=username,
        login_id=username,
    )

    trustees = await crud.get_trustees_crypto_by_election_id(
        session=session, election_id=election.id
    )

    trustee_crypto = await crud.get_trustee_crypto_by_trustee_id_election_id(
        session=session, trustee_id=trustee.id, election_id=election.id
    )

    certificates = [
        sharedpoint.Certificate.serialize(t.certificate, to_json=False)
        for t in trustees
    ]
    points = await crud.format_points_sent_to(
        session=session,
        election_id=election.id,
        trustee_id=trustee_crypto.trustee_election_id,
    )
    encrypted_tally = await crud.get_tally_by_election_id(
        session=session, election_id=election.id
    )
    encrypted_tally = [schemas.TallyBase.from_orm(tally) for tally in encrypted_tally]
    return {
        "election": schemas.ElectionOut.from_orm(election),
        "trustee": schemas.TrusteeOut.from_orm(trustee),
        "trustee_crypto": schemas.TrusteeCryptoBase.from_orm(trustee_crypto),
        "encrypted_tally": encrypted_tally,
        "certificates": psifos_utils.to_json(certificates),
        "points": psifos_utils.to_json(points),
    }


# >>> Revisar
@api_router.get(
    "/{short_name}/questions", status_code=200, response_model=schemas.BoothElectionOut
)
async def get_questions(
    request: Request,
    short_name: str,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Route for get questions
    """
    try:
        election_params = [models.Election.long_name, models.Election.short_name, models.Election.description,
                           models.Election.type, models.Election.max_weight, models.Election.public_key_id]
        _, election = await get_auth_voter_and_election(
            session=session,
            short_name=short_name,
            username=username,
            election_params=election_params,
            status="Started",
        )

        questions = await crud.get_questions_by_election_id(
            session=session, election_id=election.id
        )

        public_key = await crypto_crud.get_public_key(
            session=session, id=election.public_key_id
        )

        election_schema = schemas.ElectionOut.from_orm(election)
        election_schema.public_key = public_key
        booth = schemas.BoothElectionOut(
            election=election_schema,
            questions=[schemas.QuestionBase.from_orm(q) for q in questions],
        )
    except HTTPException: 
        logger.error("%s - Invalid Voter Access: %s (%s)" % (request.client.host, username, short_name))
        raise HTTPException(status_code=400, detail="voter not found")
    else:
        logger.log("PSIFOS", "%s - Valid Voter Access: %s (%s)" % (request.client.host, username, election.short_name))
        return booth

@api_router.get("/{short_name}/get-certificate", status_code=200)
async def get_pdf(
    short_name: str,
    username: str = Depends(AuthUser()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Return the certificate of the last vote cast by the authenticated voter

    """
    election = await crud.get_election_by_short_name(
        session=session, short_name=short_name, simple=True
    )
    voter = await crud.get_voter_by_login_id_and_election_id(
        session=session, username=username, election_id=election.id
    )
    cast_vote = await crud.get_cast_vote_by_voter_id(session=session, voter_id=voter.id)

    hash_vote = cast_vote.encrypted_ballot_hash

    link_ballot = (
        APP_FRONTEND_URL
        + "psifos/booth/"
        + short_name
        + "/public-info?hash="
        + urllib.parse.quote(hash_vote)
    )
    img = qrcode.make(link_ballot)
    buffer = BytesIO()
    img.save(buffer, "PNG")
    img_str = b64encode(buffer.getvalue()).decode("ascii")

    with open("templates/uchile-logo.jpg", "rb") as image:
        uch_str = b64encode(image.read()).decode("ascii")

    with open("templates/participa-logo.png", "rb") as image:
        par_str = b64encode(image.read()).decode("ascii")

    with open("templates/Inter-VariableFont.ttf", "rb") as font:
        font_str = b64encode(font.read()).decode("ascii")

    pdf_data = {
        "hash_vote": hash_vote,
        "election_name": election.long_name,
        "cast_at": cast_vote.cast_at,
        "font_str": font_str,
        "uch_str": uch_str,
        "par_str": par_str,
        "img_str": img_str,
        "link_ballot": link_ballot,
    }

    pdf = templates.get_template("vote_certificate.html")
    pdf = pdf.render(**pdf_data)
    result = pdfkit.from_string(pdf, css="templates/vote_certificate.css")
    return Response(result, media_type="application/pdf")


@api_router.post("/{short_name}/count-logs", status_code=200)
async def get_count_logs_by_date(
    short_name: str,
    data: dict = {},
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Return the number of logs per deltaTime from the start of the election until it ends

    """

    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )

    states_without_data = ["Setting up", "Ready for key generation", "Ready for opening"]
    if election.status in states_without_data:
        return {}
    
    logs_init = await crud.get_logs_by_type(
        session=session, election_id=election.id, type_log="voting_started"
    )
    logs_end = await crud.get_logs_by_type(
        session=session, election_id=election.id, type_log="voting_stopped"
    )

    date_init = logs_init[0].created_at if logs_init else None
    date_end = (
        logs_end[0].created_at if logs_end else psifos_utils.tz_now()
    )
    date_end = datetime.datetime(
        year=date_end.year,
        month=date_end.month,
        day=date_end.day,
        hour=date_end.hour,
        minute=date_end.minute,
        second=date_end.second,
    )

    delta_minutes = data.get("minutes", 60)
    type_log = data.get("type_log", None)
    count_logs = {}
    total = 0

    while date_init <= date_end:
        date_delta = date_init + timedelta(minutes=delta_minutes)
        dates = await crud.count_logs_by_date(
            session=session,
            election_id=election.id,
            init_date=date_init,
            end_date=date_delta,
            type_log=type_log,
        )
        count_date = len(dates)
        total += count_date
        count_logs[str(date_init)] = count_date
        date_init = date_delta

    return {"count_logs": count_logs, "total_logs": total}


@api_router.get("/{short_name}/logs/invalid-voters-logging", status_code=200)
async def get_invalid_voters_logging(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Return the logs from invalid logging

    """
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )

    logs = await crud.get_logs_by_type(
        session=session, election_id=election.id, type_log="voter_login_fail"
    )
    results = []
    for log in logs:
        json_data = psifos_utils.from_json(log[1])
        user = json_data["user"]
        date = log[0]
        results.append({"time": date, "user": user})

    return results


@api_router.get("/{short_name}/logs/voters-valid-vote", status_code=200)
async def get_voters_valid_vote(
    short_name: str,
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Return info of voters with valid votes

    """
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )
    voters_with_valid_votes = await crud.get_voters_with_valid_vote(
        session=session, election_id=election.id
    )
    result = []
    for voter in voters_with_valid_votes:
        result.append(
            {
                "voter_id": voter.username,
                "name": voter.voter_name,
                "cast_at": voter.cast_vote.cast_at,
            }
        )
    return result


@api_router.post("/{short_name}/set-status-election", status_code=200)
async def set_status_election(
    short_name: str,
    data: dict = {},
    current_user: models.User = Depends(AuthAdmin()),
    session: Session | AsyncSession = Depends(get_session),
):
    """
    Return the logs from invalid logging

    """
    status = data["status"]
    election = await get_auth_election(
        short_name=short_name, current_user=current_user, session=session
    )

    await crud.update_election(
        session=session, election_id=election.id, fields={"status": status}
    )

    return "Success"


# <<<
