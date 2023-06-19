"""
CRUD utils for Psifos
(Create - Read - Update - delete)

01/08/2022
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.psifos import utils
from app.psifos.crypto.sharedpoint import Point
from app.psifos.model import models, schemas
from sqlalchemy import select, update, delete
from sqlalchemy.orm import selectinload, defer
from app.database import db_handler

ELECTION_QUERY_OPTIONS = [

    selectinload(models.Election.trustees),
    selectinload(models.Election.sharedpoints),
    selectinload(models.Election.audited_ballots),
    defer(models.Election.encrypted_tally)
]

COMPLETE_ELECTION_QUERY_OPTIONS = [
    selectinload(models.Election.trustees),
    selectinload(models.Election.sharedpoints),
    selectinload(models.Election.audited_ballots),
    selectinload(models.Election.voters)
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


async def get_voter_by_login_id_and_election_id(session: Session | AsyncSession, voter_login_id: int, election_id: int):
    query = select(models.Voter).where(
        models.Voter.voter_login_id == voter_login_id,
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


async def get_voter_by_uuid_and_election_id(voter_uuid: str, session: Session | AsyncSession, election_id: int):
    query = select(models.Voter).where(
        models.Voter.election_id == election_id,
        models.Voter.uuid == voter_uuid
    ).options(
        VOTER_QUERY_OPTIONS
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def edit_voter(voter_uuid: str, session: Session | AsyncSession, election_id: int, fields: dict):
    query = update(models.Voter).where(
        models.Voter.election_id == election_id,
        models.Voter.uuid == voter_uuid
    ).values(fields)
    await db_handler.execute(session, query)
    await db_handler.commit(session)

    return await get_voter_by_uuid_and_election_id(voter_uuid=voter_uuid, session=session, election_id=election_id)


async def create_voter(session: Session | AsyncSession, election_id: str, uuid: str, voter: schemas.VoterIn):
    db_voter = models.Voter(election_id=election_id, uuid=uuid, **voter.dict())
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


async def delete_election_voter(session: Session | AsyncSession,  election_id, voter_uuid):
    query = delete(models.Voter).where(models.Voter.election_id ==
                                       election_id, models.Voter.uuid == voter_uuid)
    await db_handler.execute(session, query)
    await db_handler.commit(session)


# ----- CastVote CRUD Utils -----


async def get_cast_vote_by_voter_id(session: Session | AsyncSession, voter_id: int):
    query = select(models.CastVote).where(
        models.CastVote.voter_id == voter_id,
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def get_cast_vote_by_hash(session: Session | AsyncSession, hash_vote: str):
    query = select(models.CastVote).where(
        models.CastVote.vote_hash == hash_vote
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


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
    query = select(models.Trustee).where(
        models.Trustee.uuid == uuid,
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def get_by_login_id_and_election_id(session: Session | AsyncSession, trustee_login_id: str, election_id: int):
    query = select(models.Trustee).where(
        models.Trustee.trustee_login_id == trustee_login_id,
        models.Trustee.election_id == election_id
    )
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def get_trustees_by_election_id(session: Session | AsyncSession, election_id: int):
    query = select(models.Trustee).where(
        models.Trustee.election_id == election_id)
    result = await db_handler.execute(session, query)
    return result.scalars().all()


async def get_next_trustee_id(session: Session | AsyncSession, election_id: int):
    trustees = await get_trustees_by_election_id(session=session, election_id=election_id)
    return 1 if len(trustees) == 0 else max(trustees, key=(lambda t: t.trustee_id)).trustee_id + 1


async def get_global_trustee_step(session: Session | AsyncSession, election_id: int):
    trustees = await get_trustees_by_election_id(session=session, election_id=election_id)
    trustee_steps = [t.current_step for t in trustees]
    return 0 if len(trustee_steps) == 0 else min(trustee_steps)


async def create_trustee(session: Session | AsyncSession, election_id: int, uuid: str, trustee_id: int, trustee: schemas.TrusteeIn):
    db_trustee = models.Trustee(
        election_id=election_id,
        uuid=uuid,
        trustee_id=trustee_id,
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


async def delete_trustee(session: Session | AsyncSession, election_id: int, uuid: str):
    query = delete(models.Trustee).where(
        models.Trustee.uuid == uuid,
        models.Trustee.election_id == election_id
    )
    await db_handler.execute(session, query)
    await db_handler.commit(session)


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


async def create_election(session: Session | AsyncSession, election: schemas.ElectionIn, admin_id: int, uuid: str):
    db_election = models.Election(
        **election.dict(), admin_id=admin_id, uuid=uuid)
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


# --- PsifosLog CRUD Utils ---

async def log_to_db(session: Session | AsyncSession, election_id: int, log_level: str, event: str, event_params: str, created_at: str):
    db_log = models.ElectionLog(
        election_id=election_id,
        log_level=log_level,
        event=event,
        event_params=event_params,
        created_at=created_at,
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