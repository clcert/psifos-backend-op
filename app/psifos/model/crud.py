"""
CRUD utils for Psifos
(Create - Read - Update - delete)

01/08/2022
"""

from sqlalchemy.orm import Session

from app.psifos import utils
from app.psifos.crypto.sharedpoint import Point
from app.psifos.model import models, schemas



# ----- Voter CRUD Utils -----


def get_voter_by_login_id_and_election_id(db: Session, login_id: int, election_id: int):
    return (
        db.query(models.Voter)
        .filter(models.Voter.login_id == login_id, models.Voter.election_id == election_id)
        .first()
    )


def get_voters_by_election_id(db: Session, election_id: int):
    return db.query(models.Voter).filter(models.Voter.election_id == election_id).all()


def create_voter(db: Session, election_id: str, uuid: str, voter: schemas.VoterIn):
    db_voter = models.Voter(election_id=election_id, uuid=uuid, **voter.dict())
    db.add(db_voter)
    db.commit()
    db.refresh(db_voter)

    db_cast_vote = models.CastVote(voter_id=db_voter.id)
    db.add(db_cast_vote)
    db.commit()
    db.refresh(db_cast_vote)
    
    return db_voter, db_cast_vote

def delete_election_voters(db: Session, election_id: int):
    db.query(models.Voter).filter(models.Voter.election_id == election_id).delete()
    db.commit()

    
# ----- CastVote CRUD Utils -----


def get_cast_vote_by_voter_id(db: Session, voter_id: int):
    return (
        db.query(models.Voter)
        .filter(
            models.CastVote.voter_id == voter_id,
        )
        .first()
    )


def create_cast_vote(db: Session, voter_id: int):
    db_cast_vote = models.CastVote(voter_id=voter_id)
    db.add(db_cast_vote)
    db.commit()
    db.refresh(db_cast_vote)
    return db_cast_vote


def update_cast_vote(db: Session, voter_id: int, fields: dict):
    db_cast_vote = db.query(models.CastVote).filter(models.CastVote.voter_id == voter_id).update(fields)
    db.add(db_cast_vote)
    db.commit()
    db.refresh(db_cast_vote)
    return db_cast_vote


# ----- AuditedBallot CRUD Utils -----
# (TODO)

# ----- Trustee CRUD Utils -----


def get_trustee_by_uuid(db: Session, uuid: str):
    return (
        db.query(models.Trustee)
        .filter(
            models.Trustee.uuid == uuid,
        )
        .first()
    )


def get_by_login_id_and_election_id(db: Session, trustee_login_id: str, election_id: int):
    return (
        db.query(models.Trustee)
        .filter(models.Trustee.trustee_login_id == trustee_login_id, models.Trustee.election_id == election_id)
        .first()
    )


def get_trustees_by_election_id(db: Session, election_id: int):
    return db.query(models.Trustee).filter(models.Trustee.election_id == election_id).all()

def get_next_trustee_id(db: Session, election_id: int):
    trustees = get_trustees_by_election_id(db=db, election_id=election_id)
    return 1 if len(trustees) == 0 else max(trustees, key=(lambda t: t.trustee_id)).trustee_id + 1


def get_global_trustee_step(db: Session, election_id: int):
    trustees = get_trustees_by_election_id(db=db, election_id=election_id)
    trustee_steps = [t.current_step for t in trustees]
    return 0 if len(trustee_steps) == 0 else min(trustee_steps)

def create_trustee(db: Session, election_id: int, uuid: str, trustee_id: int, trustee: schemas.TrusteeIn):
    db_trustee = models.Trustee(
        election_id=election_id,
        uuid=uuid,
        trustee_id=trustee_id,
        **trustee.dict()
    )
    db.add(db_trustee)
    db.commit()
    db.refresh(db_trustee)
    return db_trustee

def update_trustee(db: Session, trustee_id: int, fields: dict):
    query_set = db.query(models.Trustee).filter(models.Trustee.id == trustee_id)
    query_set.update(fields)
    db_trustee = query_set.first()
    db.add(db_trustee)
    db.commit()
    db.refresh(db_trustee)
    return db_trustee

def delete_trustee(db: Session, election_id: int, uuid: str):
    query_trustee = db.query(models.Trustee).filter(models.Trustee.uuid == uuid)
    if query_trustee.first().election_id == election_id:
        query_trustee.delete()
        db.commit()


# ----- SharedPoint CRUD Utils -----

def create_shared_points(db: Session, election_id: int, sender: int, points: list[Point]):
    for i in range(len(points)):
        db_shared_point = models.SharedPoint(
            election_id=election_id,
            sender=sender,
            recipient=i+1,
            point=points[i]
        )
        db.add(db_shared_point)
    db.commit()


def get_shared_points_by_sender(db: Session, sender: int):
    return db.query(models.SharedPoint).filter(models.SharedPoint.sender == sender).all()


def format_points_sent_to(db: Session, election_id: int, trustee_id: int):
    points = db.query(models.SharedPoint).filter(
        models.SharedPoint.election_id == election_id, models.SharedPoint.recipient == trustee_id
    ).all()
    points.sort(key=(lambda x: x.sender))
    return utils.format_points(points)

def delete_shared_points_by_sender(db: Session, sender: int):
    db.query(models.SharedPoint).filter(models.SharedPoint.sender == sender).delete()
    db.commit()


def format_points_sent_by(db: Session, election_id: int, trustee_id: int):
    points = db.query(models.SharedPoint).filter(
        models.SharedPoint.election_id == election_id, models.SharedPoint.sender == trustee_id
    )
    points.sort(key=(lambda x: x.recipient))
    return utils.format_points(points)


# ----- Election CRUD Utils -----


def get_election_by_short_name(db: Session, short_name: str):
    return db.query(models.Election).filter(models.Election.short_name == short_name).first()


def get_election_by_uuid(db: Session, uuid: str):
    return db.query(models.Election).filter(models.Election.uuid == uuid).first()

def get_elections_by_user(db: Session, admin_id: int):
    return db.query(models.Election).filter(models.Election.admin_id == admin_id).all()


def get_num_casted_votes(db: Session, election_id: int):
    voters = get_voters_by_election_id(db=db, election_id=election_id)
    return len([v for v in voters if v.cast_vote.valid_cast_votes >= 1])


def create_election(db: Session, election: schemas.ElectionIn, admin_id: int, uuid: str):
    db_election = models.Election(**election.dict(), admin_id=admin_id, uuid=uuid)
    db.add(db_election)
    db.commit()
    db.refresh(db_election)
    return db_election


def edit_election(db: Session, election_id: int, election: schemas.ElectionIn):
    query_set = db.query(models.Election).filter(models.Election.id == election_id)
    query_set.update(election.dict())
    db_election = query_set.first()
    db.add(db_election)
    db.commit()
    db.refresh(db_election)
    return db_election


def update_election(db: Session, election_id: int, fields: dict):
    query_set = db.query(models.Election).filter(models.Election.id == election_id)
    query_set.update(fields)
    db_election = query_set.first()
    db.add(db_election)
    db.commit()
    db.refresh(db_election)
    return db_election

def edit_questions(db: Session, db_election: models.Election, questions: list):
    db_election.questions = questions
    db.add(db_election)
    db.commit()
    db.refresh(db_election)
    return db_election