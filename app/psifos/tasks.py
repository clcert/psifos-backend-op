"""
Async celery tasks for Psifos (psifos module)

lib: celery
broker: redis
gui: flower

31-08-2022
"""


import uuid
from fastapi import UploadFile
from app.celery_worker import celery
from sqlalchemy.orm import Session
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from app.psifos.model import crud, models, schemas


@celery.task(name="process_castvote")
def process_cast_vote(
    encrypted_vote: EncryptedVote, election: models.Election, voter: models.Voter, cast_ip: str, db: Session
):
    """
    Verifies if a cast_vote is valid, if so then
    it stores it in the database.
    """

    verified, fields = voter.cast_vote.process_cast_vote(encrypted_vote, election, voter, cast_ip)
    cast_vote = crud.update_cast_vote(db=db, voter_id=voter.id, fields=fields)
    return verified, cast_vote.vote_fingerprint if verified else verified, None


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
def upload_voters(election: models.Election, voter_file: UploadFile, db: Session):
    """
    Handles the upload of a voter file.
    """
    try:
        voters = [schemas.VoterIn(v) for v in models.Voter.upload_voters(voter_file)]
    except:
        return False, 0, 0

    k = 0  # voter counter
    n = len(voters)  # total voters
    for voter in voters:
        # check if voter already exists
        if crud.get_voter_by_login_id_and_election_id(db=db, voter_login_id=voter.voter_login_id):
            continue

        # add the voter to the database
        crud.create_voter(db=db, election_id=election.id, uuid=str(uuid.uuid1()), voter=voter)
        k += 1

    # update the total_voters field of election
    crud.update_election(db=db, election_id=election.id, fields={"total_voters": election.total_voters + k})
    return True, k, n
