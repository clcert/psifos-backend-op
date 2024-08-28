from app.psifos.model import models
from app.psifos.model.results import Results
from app.psifos.model.schemas import schemas
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from sqlalchemy.orm import selectinload, defer

ELECTION_QUERY_OPTIONS = [

    selectinload(models.Election.trustees),
    selectinload(models.Election.sharedpoints),
    selectinload(models.Election.audited_ballots),
    selectinload(models.Election.questions),
    selectinload(models.Election.result),
    defer(models.Election.encrypted_tally)
]

def get_election_by_uuid(session: Session, uuid: str):
    query = select(models.Election).where(models.Election.uuid == uuid).options(
        *ELECTION_QUERY_OPTIONS
    )
    result = session.execute(query)
    return result.scalars().first()

def get_voter_by_voter_id(session: Session, voter_id: int):
    query = select(models.Voter).where(models.Voter.id == voter_id)
    result = session.execute(query)
    return result.scalars().first()

def get_cast_vote_by_voter_id(session: Session, voter_id: int):
    query = select(models.CastVote).where(
        models.CastVote.voter_id == voter_id,
    )
    result = session.execute(query)
    return result.scalars().first()

def update_or_create_cast_vote(session: Session, voter_id: int, fields: dict):
    voter_query = select(models.Voter).where(
        models.Voter.id == voter_id
    )

    voter = session.execute(voter_query).scalars().first()
    
    if voter.cast_vote is None:
        db_cast_vote = models.CastVote(voter_id=voter_id, **fields)
        session.add(db_cast_vote)
    
    else:
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
    query = update(models.Election).where(
        models.Election.id == election_id
    ).values(fields)
    session.execute(query)
    session.commit()
    return get_election_by_id(session=session, election_id=election_id)

def update_election_tally(session: Session, election_id: int, key: str, new_value):
    query = select(models.Election).where(models.Election.id == election_id)
    election = session.execute(query).scalars().first()
    data = {
        key: new_value
    }
    if election.encrypted_tally:
        encrypted_tally = election.encrypted_tally
        encrypted_tally.update(data)
        data = encrypted_tally

    query = update(models.Election).where(
    models.Election.id == election_id
    ).values(encrypted_tally=data)
    session.execute(query)
    session.commit()

def get_voters_by_election_id_and_group(session: Session, election_id: int, group: str, page=0, page_size=None):
    query = select(models.Voter).where(models.Voter.election_id == election_id, models.Voter.group == group).offset(page).limit(page_size)
    result = session.execute(query)
    return result.scalars().all()

def get_groups_voters(session: Session, election_id: int):
    query = select(models.Voter.group).where(
        models.Voter.election_id == election_id
    ).distinct()
    result = session.execute(query)
    return result.fetchall()


def get_voter_by_login_id_and_election_id(session: Session, voter_login_id: int, election_id: int):
    query = select(models.Voter).where(
        models.Voter.voter_login_id == voter_login_id,
        models.Voter.election_id == election_id
    )
    result = session.execute(query)
    return result.scalars().first()

def create_voter(session: Session, election_id: int, voter: schemas.VoterIn):
    db_voter = models.Voter(election_id=election_id, **voter.dict())
    session.add(db_voter)
    session.commit()
    session.refresh(db_voter)

    # db_cast_vote = models.CastVote(voter_id=db_voter.id)
    # session.add(db_cast_vote)
    # session.commit()
    # session.refresh(db_cast_vote)
    
    return db_voter #, db_cast_vote

def update_voter(session: Session, voter_id: int, fields: dict):
    query = update(models.Voter).where(
        models.Voter.id == voter_id
    ).values(fields)
    
    session.execute(query)
    session.commit()

    return get_voter_by_voter_id(session=session, voter_id=voter_id)


def get_public_key(session: Session, id: int):
    query = select(models.PublicKey).where(models.PublicKey.id == id)
    result = session.execute(query)
    return result.scalars().first()

def create_result(session: Session, election_id: int, result: dict):

    db_result = Results(election_id=election_id, **result)
    session.add(db_result)
    session.commit()
    return db_result