"""
CRUD utils for Psifos
(Create - Read - Update - delete)

01/08/2022
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlalchemy import and_, func

from app.psifos import utils
from app.psifos.crypto.sharedpoint import Point
from app.psifos.model import models
from app.psifos.model.decryptions import DecryptionFactory, HomomorphicDecryption, MixnetDecryption
from app.psifos.model.schemas import schemas
from app.psifos.model.enums import TrusteeStepEnum
from sqlalchemy import select, update, delete
from sqlalchemy.orm import selectinload, defer, joinedload, with_polymorphic
from app.database import db_handler


ELECTION_QUERY_OPTIONS = [

    selectinload(models.Election.trustees),
    selectinload(models.Election.sharedpoints),
    selectinload(models.Election.audited_ballots),
    selectinload(models.Election.questions),
    selectinload(models.Election.result),
    selectinload(models.Election.public_key),
]

COMPLETE_ELECTION_QUERY_OPTIONS = [
    selectinload(models.Election.trustees),
    selectinload(models.Election.sharedpoints),
    selectinload(models.Election.audited_ballots),
    selectinload(models.Election.voters),
    selectinload(models.Election.questions),
    selectinload(models.Election.result),
    selectinload(models.Election.public_key),
]

TRUSTEE_QUERY_OPTIONS = [
    joinedload(models.TrusteeCrypto.public_key),
    selectinload(models.TrusteeCrypto.decryptions_homomorphic),
    selectinload(models.TrusteeCrypto.decryptions_mixnet),
]


VOTER_QUERY_OPTIONS = selectinload(
    models.Voter.cast_vote
)


# ----- Voter CRUD Utils -----


async def get_voter_by_name_and_id(session: Session, voter_name: str, election_id: int):
    query = select(models.Voter).where(
        models.Voter.voter_name == voter_name,
        models.Voter.election_id == election_id
    ).options(
        VOTER_QUERY_OPTIONS
    )
    result = await db_handler.execute(session, query)
    return result.scalars().all()


async def get_voter_by_voter_id(session: Session | AsyncSession, voter_id: int):
    query = select(models.Voter).where(models.Voter.id == voter_id).options(
        VOTER_QUERY_OPTIONS
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def get_voter_by_login_id_and_election_id(session: Session | AsyncSession, username: int, election_id: int):
    query = select(models.Voter).where(
        models.Voter.username == username,
        models.Voter.election_id == election_id
    ).options(
        VOTER_QUERY_OPTIONS
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def get_voters_by_election_id(session: Session | AsyncSession, election_id: int, page=0, page_size=None):
    query = select(models.Voter).where(models.Voter.election_id == election_id).offset(page).limit(page_size).options(
        VOTER_QUERY_OPTIONS
    )
    result = await db_handler.execute(session, query)
    return result.scalars().all()


async def get_voters_with_valid_vote(session: Session | AsyncSession, election_id: int):
    voters = await get_voters_by_election_id(session=session, election_id=election_id)
    return [v for v in voters if v.valid_cast_votes >= 1]


async def get_voter_by_login_id_and_election_id(session: Session | AsyncSession, username: str, election_id: int):
    query = select(models.Voter).where(
        models.Voter.election_id == election_id,
        models.Voter.username == username
    ).options(
        VOTER_QUERY_OPTIONS
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def edit_voter(username: str, session: Session | AsyncSession, election_id: int, fields: dict):
    query = update(models.Voter).where(
        models.Voter.election_id == election_id,
        models.Voter.username == username
    ).values(fields)
    await db_handler.execute(session, query)
    await db_handler.commit(session)

    return await get_voter_by_login_id_and_election_id(username=username, session=session, election_id=election_id)


async def create_voter(session: Session | AsyncSession, election_id: str, voter: schemas.VoterIn):
    db_voter = models.Voter(election_id=election_id, **voter.dict())
    db_handler.add(session, db_voter)
    await db_handler.commit(session)
    await db_handler.refresh(session, db_voter)

    db_cast_vote = models.CastVote(voter_id=db_voter.id)
    db_handler.add(session, db_cast_vote)
    await db_handler.commit(session)
    await db_handler.refresh(session, db_cast_vote)

    return db_voter, db_cast_vote


async def delete_election_voters(session: Session | AsyncSession, election_id: int):
    query = delete(models.Voter).where(models.Voter.election_id == election_id)
    await db_handler.execute(session, query)
    await db_handler.commit(session)


async def delete_election_voter(session: Session | AsyncSession,  election_id, username):
    query = delete(models.Voter).where(models.Voter.election_id ==
                                       election_id, models.Voter.username == username)
    await db_handler.execute(session, query)
    await db_handler.commit(session)

async def has_valid_vote(session: Session | AsyncSession, election_id: int, username: str):
    query = select(models.Voter).join(
        models.CastVote, models.CastVote.voter_id == models.Voter.id).where(
        models.Voter.election_id == election_id,
        models.Voter.username == username,
        models.CastVote.is_valid
    )
    result = await db_handler.execute(session, query)
    return len(result.all()) > 0


# ----- CastVote CRUD Utils -----


async def get_cast_vote_by_voter_id(session: Session | AsyncSession, voter_id: int):
    query = select(models.CastVote).where(
        models.CastVote.voter_id == voter_id,
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def get_cast_vote_by_hash(session: Session | AsyncSession, hash_vote: str):
    query = select(models.CastVote).where(
        models.CastVote.encrypted_ballot_hash == hash_vote
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()

async def get_count_valid_cast_votes_by_election_id(session: Session | AsyncSession, election_id: int):
    query = select(func.count(models.CastVote.id)).join(
        models.Voter, models.Voter.id == models.CastVote.voter_id).where(
        models.Voter.election_id == election_id,
        models.CastVote.is_valid,
    )
    result = await db_handler.execute(session, query)
    return result.scalar()

async def count_cast_vote_by_date(session: Session | AsyncSession, init_date, end_date, election_id: int):

    query = select(models.CastVote.cast_at).join(
        models.Voter, models.Voter.id == models.CastVote.voter_id).where(
            models.Voter.election_id == election_id,
            and_(models.CastVote.cast_at >= init_date,
                 models.CastVote.cast_at <= end_date))
    result = await db_handler.execute(session, query)
    return result.all()


async def create_cast_vote(session: Session | AsyncSession, voter_id: int):
    db_cast_vote = models.CastVote(voter_id=voter_id)
    db_handler.add(session, db_cast_vote)
    await db_handler.commit(session)
    await db_handler.refresh(session, db_cast_vote)
    return db_cast_vote


async def update_cast_vote(session: Session | AsyncSession, voter_id: int, fields: dict):
    query = update(models.CastVote).where(
        models.CastVote.voter_id == voter_id
    ).values(fields)
    await db_handler.execute(session, query)
    await db_handler.commit(session)

    return await get_cast_vote_by_voter_id(session=session, voter_id=voter_id)


# ----- AuditedBallot CRUD Utils -----
# (TODO)

# ----- Trustee CRUD Utils -----

async def get_trustee_by_id(session: Session | AsyncSession, id: int):
    query = select(models.Trustee).where(
        models.Trustee.id == id,
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def get_trustee_by_uuid(session: Session | AsyncSession, uuid: str):
    query = select(models.Trustee, models.TrusteeCrypto).join(
        models.TrusteeCrypto, models.TrusteeCrypto.trustee_id == models.Trustee.id).where(
        models.Trustee.uuid == uuid,
    ).options(*TRUSTEE_QUERY_OPTIONS)
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def get_trustee_panel(session: Session | AsyncSession, trustee_id: int):
    query = select(models.TrusteeCrypto, models.Election.short_name).join(
        models.Election, models.TrusteeCrypto.election_id == models.Election.id).where(
        models.TrusteeCrypto.trustee_id == trustee_id
    ).options(
        selectinload(
            models.TrusteeCrypto.public_key
        )
    )
    result = await db_handler.execute(session, query)
    return result.scalars().all()


async def get_by_login_id_and_election_id(session: Session | AsyncSession, trustee_login_id: str, election_id: int):
    query = select(models.Trustee).join(
        models.TrusteeCrypto, models.TrusteeCrypto.trustee_id == models.Trustee.id).where(
        models.Trustee.trustee_login_id == trustee_login_id,
        models.TrusteeCrypto.election_id == election_id
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()

async def get_trustee_by_username(session: Session | AsyncSession, username: str):
    query = select(models.Trustee).where(
        models.Trustee.username == username
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def get_trustees_by_election_id(session: Session | AsyncSession, election_id: int):
    query = select(models.Trustee).join(
        models.TrusteeCrypto, models.TrusteeCrypto.trustee_id == models.Trustee.id).where(
        models.TrusteeCrypto.election_id == election_id
    ).options(
        selectinload(
            models.Trustee.trustee_crypto
        )
    )

    result = await db_handler.execute(session, query)
    result = result.scalars().all()
    return result

async def get_trustees_params_by_election_id(session: Session | AsyncSession, election_id: int, params: list):
    # Explicitly specify the initial table with select_from
    query = (
        select(*params)
        .select_from(models.TrusteeCrypto)  # Start from TrusteeCrypto
        .join(models.Trustee, models.TrusteeCrypto.trustee_id == models.Trustee.id)  # Explicit join condition
        .where(models.TrusteeCrypto.election_id == election_id)  # Filter by election_id
    )
    result = await db_handler.execute(session, query)
    return result.all()

async def get_crypto_trustees_by_election_id(session: Session | AsyncSession, election_id: int):
    query = select(models.TrusteeCrypto).where(
        models.TrusteeCrypto.election_id == election_id).options(*TRUSTEE_QUERY_OPTIONS)
    result = await db_handler.execute(session, query)
    return result.scalars().all()

async def get_simple_trustees_by_election_id(session: Session | AsyncSession, election_id: int):
    query = select(models.TrusteeCrypto).where(
        models.TrusteeCrypto.election_id == election_id)
    result = await db_handler.execute(session, query)
    return result.scalars().all()

async def get_next_trustee_id(session: Session | AsyncSession, election_id: int):
    trustees = await get_crypto_trustees_by_election_id(session=session, election_id=election_id)
    return 1 if len(trustees) == 0 else max(trustees, key=(lambda t: t.trustee_election_id)).trustee_election_id + 1


async def get_global_trustee_step(session: Session | AsyncSession, election_id: int):
    trustees = await get_trustees_crypto_by_election_id(session=session, election_id=election_id)
    trustee_steps = [t.current_step for t in trustees]
    return 0 if len(trustee_steps) == 0 else min(trustee_steps)


async def create_trustee(session: Session | AsyncSession, trustee: schemas.TrusteeIn):
    db_trustee = models.Trustee(
        **trustee.dict()
    )
    db_handler.add(session, db_trustee)
    await db_handler.commit(session)
    await db_handler.refresh(session, db_trustee)
    return db_trustee


async def update_trustee(session: Session | AsyncSession, trustee_id: int, fields: dict):
    query = update(models.Trustee).where(
        models.Trustee.id == trustee_id
    ).values(fields)
    await db_handler.execute(session, query)
    await db_handler.commit(session)

    return await get_trustee_by_id(session=session, id=trustee_id)


async def delete_trustee(session: Session | AsyncSession, uuid: str):
    query = delete(models.Trustee).where(
        models.Trustee.uuid == uuid
    )
    await db_handler.execute(session, query)
    await db_handler.commit(session)

# ----- TrusteeCrypto CRUD Utils -----

async def create_trustee_crypto(session: Session | AsyncSession, election_id: int, trustee_id: int, trustee_election_id: int):
    db_trustee_crypto = models.TrusteeCrypto(
        election_id=election_id,
        trustee_id=trustee_id,
        trustee_election_id=trustee_election_id
    )
    db_handler.add(session, db_trustee_crypto)
    await db_handler.commit(session)
    await db_handler.refresh(session, db_trustee_crypto)
    return db_trustee_crypto

async def get_trustee_crypto_by_trustee_id_election_id(session: Session | AsyncSession, trustee_id: int, election_id: int):
    query = select(models.TrusteeCrypto).where(
        models.TrusteeCrypto.trustee_id == trustee_id,
        models.TrusteeCrypto.election_id == election_id
    ).options(
        *TRUSTEE_QUERY_OPTIONS
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()

async def get_trustees_crypto_by_election_id(session: Session | AsyncSession, election_id: int):
    query = select(models.TrusteeCrypto).where(
        models.TrusteeCrypto.election_id == election_id
    )
    result = await db_handler.execute(session, query)
    return result.scalars().all()

async def get_trustees_crypto_by_trustee_id(session: Session | AsyncSession, trustee_id: int):
    query = select(models.TrusteeCrypto).where(
        models.TrusteeCrypto.trustee_id == trustee_id
    ).options(
        *TRUSTEE_QUERY_OPTIONS
    )
    result = await db_handler.execute(session, query)
    return result.scalars().all()

async def update_trustee_crypto(session: Session | AsyncSession, trustee_id: int, election_id: int, fields: dict):
    query = update(models.TrusteeCrypto).where(
        models.TrusteeCrypto.trustee_id == trustee_id,
        models.TrusteeCrypto.election_id == election_id
    ).values(fields)
    await db_handler.execute(session, query)
    await db_handler.commit(session)

    return await get_trustee_crypto_by_trustee_id_election_id(session=session, trustee_id=trustee_id, election_id=election_id)


async def delete_trustee_crypto(session: Session | AsyncSession, trustee_id: int, election_id: int):
    query = delete(models.TrusteeCrypto).where(
        models.TrusteeCrypto.trustee_id == trustee_id,
        models.TrusteeCrypto.election_id == election_id
    )
    await db_handler.execute(session, query)
    await db_handler.commit(session)

async def get_total_trustees_by_election_id(session: Session | AsyncSession, election_id: int):
    query = select(func.count(models.Trustee.id)).where(
        models.TrusteeCrypto.election_id == election_id
    )
    result = await db_handler.execute(session, query)
    return result.scalar()

# ----- SharedPoint CRUD Utils -----

async def create_shared_points(session: Session | AsyncSession, election_id: int, sender: int, points: list[Point]):
    for i in range(len(points)):
        db_shared_point = models.SharedPoint(
            election_id=election_id,
            sender=sender,
            recipient=i+1,
            point=points[i]
        )
        db_handler.add(session, db_shared_point)
    await db_handler.commit(session)


async def get_shared_points_by_sender(session: Session | AsyncSession, sender: int):
    query = select(models.SharedPoint).where(
        models.SharedPoint.sender == sender)
    result = await db_handler.execute(session, query)
    return result.scalars().all()


async def format_points_sent_to(session: Session | AsyncSession, election_id: int, trustee_id: int):
    query = select(models.SharedPoint).where(
        models.SharedPoint.election_id == election_id, models.SharedPoint.recipient == trustee_id
    )
    result = await db_handler.execute(session, query)
    points = result.scalars().all()

    points.sort(key=(lambda x: x.sender))
    return utils.format_points(points)


async def delete_shared_points_by_sender_and_election_id(session: Session | AsyncSession, sender: int, election_id: int):
    query = delete(models.SharedPoint).where(
        models.SharedPoint.sender == sender,
        models.SharedPoint.election_id == election_id
    )
    await db_handler.execute(session, query)
    await db_handler.commit(session)


async def format_points_sent_by(session: Session | AsyncSession, election_id: int, trustee_id: int):
    query = select(models.SharedPoint).where(
        models.SharedPoint.election_id == election_id, models.SharedPoint.sender == trustee_id
    )
    result = await db_handler.execute(session, query)
    points = result.scalars().all()
    points.sort(key=(lambda x: x.recipient))
    return utils.format_points(points)


# ----- Election CRUD Utils -----


async def get_election_by_short_name(session: Session | AsyncSession, short_name: str, simple: bool = False):
    options_query = ELECTION_QUERY_OPTIONS if simple else COMPLETE_ELECTION_QUERY_OPTIONS
    query = select(models.Election).where(models.Election.short_name == short_name).options(
        *options_query
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()

async def get_election_params_by_name(session: Session | AsyncSession, short_name: str, params: list):
    query = select(*params).where(models.Election.short_name == short_name)
    result = await db_handler.execute(session, query)
    return result.first()

async def get_election_by_uuid(session: Session | AsyncSession, uuid: str):
    query = select(models.Election).where(models.Election.uuid == uuid).options(
        *ELECTION_QUERY_OPTIONS
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def get_election_by_id(session: Session | AsyncSession, election_id: int):
    query = select(models.Election).where(models.Election.id == election_id).options(
        *ELECTION_QUERY_OPTIONS
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def get_elections_by_user(session: Session | AsyncSession, admin_id: int):
    query = select(models.Election).where(models.Election.admin_id == admin_id).options(
        *ELECTION_QUERY_OPTIONS
    )
    result = await db_handler.execute(session, query)
    return result.scalars().all()


async def get_num_casted_votes(session: Session | AsyncSession, election_id: int):
    voters = await get_voters_by_election_id(session=session, election_id=election_id)
    return len([v for v in voters if v.valid_cast_votes >= 1])


async def create_election(session: Session | AsyncSession, election: schemas.ElectionIn, admin_id: int):
    db_election = models.Election(
        **election.dict(), admin_id=admin_id)
    db_handler.add(session, db_election)
    await db_handler.commit(session)
    await db_handler.refresh(session, db_election)
    return db_election


async def edit_election(session: Session | AsyncSession, election_id: int, election: schemas.ElectionIn):
    query = update(models.Election).where(
        models.Election.id == election_id
    ).values(election.dict())
    await db_handler.execute(session, query)
    await db_handler.commit(session)

    return await get_election_by_id(session=session, election_id=election_id)


async def delete_election(session: Session | AsyncSession, election_id: int):
    query = delete(models.Election).where(
        models.Election.id == election_id
    )
    await db_handler.execute(session, query)
    await db_handler.commit(session)


async def update_election(session: Session | AsyncSession, election_id: int, fields: dict):
    query = update(models.Election).where(
        models.Election.id == election_id
    ).values(fields)
    await db_handler.execute(session, query)
    await db_handler.commit(session)

    return await get_election_by_id(session=session, election_id=election_id)


async def edit_questions(session: Session | AsyncSession, db_election: models.Election, questions: list):
    db_election.questions = questions
    db_handler.add(session, db_election)
    await db_handler.commit(session)
    await db_handler.refresh(session, db_election)
    return db_election

async def get_question_by_election_id_and_index(session: Session | AsyncSession, election_id: int, index: int):
    query = select(models.AbstractQuestion).where(
        models.AbstractQuestion.election_id == election_id,
        models.AbstractQuestion.index == index
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()

async def get_questions_by_election_id(session: Session | AsyncSession, election_id: int):
    query = select(models.AbstractQuestion).where(
        models.AbstractQuestion.election_id == election_id
    )
    result = await db_handler.execute(session, query)
    return result.scalars().all()

async def get_groups_by_election_id(session: Session | AsyncSession, election_id: int):
    query = select(models.Voter.group).where(models.Voter.election_id == election_id).distinct()
    result = await db_handler.execute(session, query)
    return result.scalars().all()


# --- PsifosLog CRUD Utils ---

async def log_to_db(session: Session | AsyncSession, election_id: int, log_level: str, event: str, event_params: str):
    db_log = models.ElectionLog(
        election_id=election_id,
        log_level=log_level,
        event=event,
        event_params=event_params,
    )
    db_handler.add(session, db_log)
    await db_handler.commit(session)
    await db_handler.refresh(session, db_log)
    return db_log


async def count_logs_by_date(session: Session | AsyncSession, election_id: int, init_date, end_date, type_log):

    query = select(models.ElectionLog.event).where(
        models.ElectionLog.election_id == election_id,
        models.ElectionLog.event == type_log,
        and_(models.ElectionLog.created_at >= init_date,
             models.ElectionLog.created_at <= end_date))
    result = await db_handler.execute(session, query)
    return result.all()


async def get_logs_by_type(session: Session | AsyncSession, election_id: int, type_log):

    query = select(models.ElectionLog.created_at, models.ElectionLog.event_params).where(
        models.ElectionLog.election_id == election_id,
        models.ElectionLog.event == type_log,
    )
    result = await db_handler.execute(session, query)
    return result.all()

# --- Tally CRUD Utils ---
async def get_tally_by_group(session: Session | AsyncSession, election_id: int, group: str):
    tally_polymorphic = with_polymorphic(models.Tally, "*")
    query = select(tally_polymorphic).join(
        models.AbstractQuestion, models.AbstractQuestion.id == models.Tally.question_id).where(
        models.AbstractQuestion.election_id == election_id,
        models.Tally.group == group
    )
    result = await db_handler.execute(session, query)
    return result.scalars().all()

async def get_tally_by_election_id(session: Session | AsyncSession, election_id: int):
    query = select(models.Tally, models.AbstractQuestion.index).join(
        models.AbstractQuestion, models.AbstractQuestion.id == models.Tally.question_id).where(
        models.AbstractQuestion.election_id == election_id
    )
    result = await db_handler.execute(session, query)
    return result.scalars().all()

# --- Decryption CRUD Utils ---

async def get_decryptions_homomorphic_by_trustee_id(session: Session | AsyncSession, trustee_crypto_id: int):
    query = select(HomomorphicDecryption).where(HomomorphicDecryption.trustee_crypto_id == trustee_crypto_id)
    result = await db_handler.execute(session, query)
    return result.scalars().all()

async def get_decryptions_mixnet_by_trustee_id(session: Session | AsyncSession, trustee_crypto_id: int):
    query = select(MixnetDecryption).where(MixnetDecryption.trustee_crypto_id == trustee_crypto_id)
    result = await db_handler.execute(session, query)
    return result.scalars().all()

async def get_decryptions_by_trustee_id(session: Session | AsyncSession, trustee_crypto_id: int):
    homorphic = await get_decryptions_homomorphic_by_trustee_id(session=session, trustee_crypto_id=trustee_crypto_id)
    mixnet = await get_decryptions_mixnet_by_trustee_id(session=session, trustee_crypto_id=trustee_crypto_id)
    return homorphic + mixnet

async def create_decryption(session: Session | AsyncSession, trustee_crypto_id: int, group: str, question: schemas.QuestionBase, decryption: schemas.DecryptionIn):
    decryption.group = group
    decryption.trustee_crypto_id = trustee_crypto_id
    decryption.question = question
    decryption.question_id = question.id
    db_handler.add(session, decryption)
    await db_handler.commit(session)
    await db_handler.refresh(session, decryption)
    return decryption
