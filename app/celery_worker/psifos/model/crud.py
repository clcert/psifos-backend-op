from app.psifos.model import models, schemas
from sqlalchemy import select, update
from sqlalchemy.orm import Session

def get_election_by_uuid(session: Session, uuid: str):
    query = select(models.Election).where(models.Election.uuid == uuid)
    result = session.execute(query)
    return result.scalars().first()

def get_voter_by_voter_id(session: Session, voter_id: int):
    query = select(models.Voter).where(models.Voter.id == voter_id)
    result = session.execute(query)
    return result.scalars().first()

def get_cast_vote_by_voter_id(session: Session, voter_id: int):
    query = select(models.Voter).where(
        models.CastVote.voter_id == voter_id,
    )
    result = session.execute(query)
    return result.scalars().first()

def update_cast_vote(session: Session, voter_id: int, fields: dict):
    query = update(models.CastVote).where(
        models.CastVote.voter_id == voter_id
    ).values(fields)
    session.execute(query)
    session.commit()
    return get_cast_vote_by_voter_id(session=session, voter_id=voter_id)

def get_election_by_id(session: Session, election_id: int):
    query = select(models.Election).where(models.Election.id == election_id)
    result = session.execute(query)
    return result.scalars().first()

def update_election(session: Session, election_id: int, fields: dict):
    query = select(models.Election).where(
        models.Election.id == election_id
    ).values(fields)
    session.execute(query)
    session.commit()
    return get_election_by_id(session=session, election_id=election_id)

def get_voter_by_login_id_and_election_id(session: Session, voter_login_id: int, election_id: int):
    query = select(models.Voter).where(
        models.Voter.voter_login_id == voter_login_id,
        models.Voter.election_id == election_id
    )
    result = session.execute(query)
    return result.scalars().first()

def create_voter(session: Session, election_id: str, uuid: str, voter: schemas.VoterIn):
    session_voter = models.Voter(election_id=election_id, uuid=uuid, **voter.dict())
    session.add(session_voter)
    session.commit()
    session.refresh(session_voter)
