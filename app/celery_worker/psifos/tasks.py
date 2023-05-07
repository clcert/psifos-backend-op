"""
celery tasks for Psifos (psifos module)

lib: celery
broker: redis
gui: flower

31-08-2022
"""


import uuid


from app.celery_worker import celery
from app.psifos.model import models, schemas
from app.database import SessionLocal
from .model import crud
from datetime import datetime

from app.psifos import utils as psifos_utils
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote


@celery.task(name="process_castvote")
def process_cast_vote(private_p: bool, election_uuid: str, serialized_encrypted_vote: str, cast_ip: str, **kwargs):
    """
    Verifies if a cast_vote is valid, if so then
    it stores it in the database.
    """

    with SessionLocal() as session: 
        election = crud.get_election_by_uuid(uuid=election_uuid, session=session)
        if private_p:
            voter_id = kwargs.get("voter_id")
            voter = crud.get_voter_by_voter_id(voter_id=voter_id, session=session)
        else:
            voter_login_id = kwargs.get("voter_login_id")
            voter_in = schemas.VoterIn(voter_login_id=voter_login_id, voter_name=voter_login_id, voter_weight=1)
            voter = crud.create_voter(session=session, election_id=election.id, uuid=str(uuid.uuid1()), voter=voter_in)
            crud.update_election(session=session, election_id=election.id, fields={"total_voters": election.total_voters + 1})

        enc_vote_data = psifos_utils.from_json(serialized_encrypted_vote)
        encrypted_vote = EncryptedVote(**enc_vote_data)
        is_valid, voter_fields, cast_vote_fields = voter.process_cast_vote(encrypted_vote, election, cast_ip)
        cast_vote = crud.update_or_create_cast_vote(session=session, voter_id=voter.id, fields=cast_vote_fields)
        voter = crud.update_voter(session=session, voter_id=voter.id, fields=voter_fields)
    
    if is_valid:
        return is_valid, cast_vote.vote_hash
    
    return is_valid, None


@celery.task(name="compute_tally", ignore_result=True)
def compute_tally(election_uuid: str, serialized_encrypted_votes: list[str], weights: list[int]):
    """
    Computes the encrypted tally of an election.
    """
    with SessionLocal() as session:
        election = crud.get_election_by_uuid(uuid=election_uuid, session=session)
        encrypted_votes = [EncryptedVote(**(psifos_utils.from_json(v))) for v in serialized_encrypted_votes]
        fields = election.compute_tally(encrypted_votes, weights)
        crud.update_election(session=session, election_id=election.id, fields=fields)


@celery.task(name="combine_decryptions", ignore_result=True)
def combine_decryptions(election_uuid: str):
    """
    Combines the partial decryptions of the trustees and releases
    the election results.
    """
    with SessionLocal() as session:
        election = crud.get_election_by_uuid(uuid=election_uuid, session=session)
        fields = election.combine_decryptions()
        crud.update_election(session=session, election_id=election.id, fields=fields)


@celery.task(name="upload_voters")
def upload_voters(election_uuid: str, voter_file_content: str):
    """
    Handles the upload of a voter file.
    """
    with SessionLocal() as session:
        election = crud.get_election_by_uuid(uuid=election_uuid, session=session)

        try:
            voters = [
                schemas.VoterIn(**v) 
                for v in models.Voter.upload_voters(voter_file_content)
            ]
        except Exception:
            return False, 0, 0

        k = 0  # voter counter
        n = len(voters)  # total voters
        for voter in voters:
            # check if voter already exists
            if crud.get_voter_by_login_id_and_election_id(session=session, voter_login_id=voter.voter_login_id, election_id=election.id):
                continue

            # add the voter to the database
            crud.create_voter(session=session, election_id=election.id, uuid=str(uuid.uuid1()), voter=voter)
            k += 1

        # update the total_voters field of election
        crud.update_election(session=session, election_id=election.id, fields={"total_voters": election.total_voters + k})
    return True, k, n

