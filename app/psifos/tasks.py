"""
Async celery tasks for Psifos (psifos module)

lib: celery
broker: redis
gui: flower

31-08-2022
"""

import datetime

from app.celery_worker import celery
from sqlalchemy.orm import Session
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from app.psifos.model import crud, models

@celery.task(name="process_castvote")
def process_cast_vote(encrypted_vote: EncryptedVote, election: models.Election, voter: models.Voter, cast_ip: str, db: Session):
    """
    Verifies if a cast_vote is valid, if so then
    it stores it in the database.
    """
    return models.CastVote.process(encrypted_vote, election, voter, cast_ip, db)

@celery.task(name="compute_tally")
def compute_tally(election: models.Election, encrypted_votes: list[EncryptedVote], weights: list[int], db: Session):
    """
    Computes the encrypted tally of an election.
    """
    fields = election.compute_tally(encrypted_votes, weights)
    crud.update_election(db=db, election_id=election.id, fields=fields)


@celery.task(name="combine_decryptions")
def combine_decryptions(election: models.Election, db: Session):
    """
    Combines the partial decryptions of the trustees and releases
    the election results.
    """
    fields = election.combine_decryptions()
    crud.update_election(db=db, election_id=election.id, fields=fields)


@celery.task(name="upload_voters")
def upload_voters(*args, **kwargs):
    """
    Handles the upload of a voter file.
    """
    pass


