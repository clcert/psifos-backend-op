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

from app.psifos import utils as psifos_utils
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from app.psifos.crypto.tally.tally import TallyManager
from app.psifos.crypto.utils import hash_b64
from app.psifos.model.enums import ElectionStatusEnum, ElectionLoginTypeEnum
from app.psifos.model import models
from io import StringIO

import csv



@celery.task(name="process_castvote")
def process_cast_vote(
    election_login_type: str,
    election_short_name: str,
    serialized_encrypted_vote: str,
    cast_ip: str,
    **kwargs
):
    """
    Verifies if a cast_vote is valid, if so then
    it stores it in the database.
    """

    with SessionLocal() as session:

        query_params = [
            models.Election.id,
            models.Election.total_voters,
            models.Election.questions,
            models.Election.public_key,
            models.Election.uuid
        ]

        election = crud.get_election_params_by_short_name(short_name=election_short_name, session=session, params=query_params)
        if election_login_type == ElectionLoginTypeEnum.close_p:
            voter_id = kwargs.get("voter_id")
            voter = crud.get_voter_by_voter_id(voter_id=voter_id, session=session)
        else:
            voter_login_id = kwargs.get("voter_login_id")
            voter = crud.get_voter_by_login_id_and_election_id(
                session=session, voter_login_id=voter_login_id, election_id=election.id
            )
            if not voter:
                voter_in = schemas.VoterIn(
                    voter_login_id=voter_login_id,
                    voter_name=voter_login_id,
                    login_id_election_id=f"{voter_login_id}_{election.id}",
                    voter_weight=1,
                    group="",
                )
                voter = crud.create_voter(
                    session=session,
                    election_id=election.id,
                    uuid=str(uuid.uuid1()),
                    voter=voter_in,
                )
                crud.update_election(
                    session=session,
                    election_id=election.id,
                    fields={"total_voters": election.total_voters + 1},
                )

        enc_vote_data = psifos_utils.from_json(serialized_encrypted_vote)
        encrypted_vote = EncryptedVote(**enc_vote_data)
        is_valid, voter_fields, cast_vote_fields = voter.process_cast_vote(
            encrypted_vote, election, cast_ip
        )
        cast_vote = crud.update_or_create_cast_vote(
            session=session,
            voter_id=voter.id,
            fields=cast_vote_fields,
        )
        voter = crud.update_voter(
            session=session, voter_id=voter.id, fields=voter_fields
        )

    if is_valid:
        return is_valid, cast_vote.vote_hash

    return is_valid, None


@celery.task(name="compute_tally")
def compute_tally(election_uuid: str):
    """
    Computes the encrypted tally of an election.
    """
    with SessionLocal() as session:
        election = crud.get_election_by_uuid(uuid=election_uuid, session=session)
        voters_group = crud.get_groups_voters(session=session, election_id=election.id)
        tally_grouped = []
        for voter_group in voters_group:
            group = voter_group[0]
            voters = crud.get_voters_by_election_id_and_group(
                session=session, election_id=election.id, group=group
            )
            not_null_voters = [
                v for v in voters if (v.valid_cast_votes >= 1)
            ]
            serialized_encrypted_votes = [
                EncryptedVote.serialize(v.cast_vote.vote) for v in not_null_voters
            ]
            weights = [v.voter_weight for v in not_null_voters]
            encrypted_votes = [
                EncryptedVote(**(psifos_utils.from_json(v)))
                for v in serialized_encrypted_votes
            ]
            tally = election.compute_tally(encrypted_votes, weights, group)
            tally_grouped.append(tally)

        tally_manager = TallyManager(*tally_grouped)
        fields = {
            "encrypted_tally": tally_manager,
            "election_status": ElectionStatusEnum.tally_computed,
            "encrypted_tally_hash": hash_b64(TallyManager.serialize(tally_manager)),
        }
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
            grouped = election.grouped
            buffer = StringIO(voter_file_content)
            csv_reader = csv.reader(buffer, delimiter=",")
            k = 0  # voter counter
            n = 0 # total voters
            for voter in csv_reader:
                n += 1
                add_group = len(voter) > 3 and grouped
                v_in =  {
                        "voter_login_id": voter[0],
                        "voter_name": voter[1],
                        "voter_weight": voter[2],
                        "login_id_election_id": f"{voter[0]}_{election.id}",
                        "group": voter[3] if add_group else ""
                    }
                v_in = schemas.VoterIn(**v_in)

                # add the voter to the database
                new_voter = crud.create_voter(
                    session=session,
                    election_id=election.id,
                    uuid=str(uuid.uuid1()),
                    voter=v_in,
                )
                if new_voter:
                    k += 1    

            # update the total_voters field of election
            crud.update_election(
                session=session,
                election_id=election.id,
                fields={"total_voters": election.total_voters + k},
            )
        except Exception as e:
            return False, 0, 0
        
    return True, k, n
