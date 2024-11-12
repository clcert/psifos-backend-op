"""
celery tasks for Psifos (psifos module)

lib: celery
broker: redis
gui: flower

31-08-2022
"""


import uuid


from app.celery_worker import celery
from app.psifos.model.schemas import schemas
from app.psifos.model import models
from app.database import SessionLocal
from .model import crud


from app.psifos import utils as psifos_utils
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from app.psifos.model.crypto_models import PublicKey
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
            models.Election.uuid,
            models.Election.public_key_id,
        ]

        election = crud.get_election_params_by_short_name(short_name=election_short_name, session=session, params=query_params)
        questions = crud.get_questions_by_election_id(election_id=election.id, session=session)
        public_key = crud.get_public_key(session=session, id=election.public_key_id)
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
            encrypted_vote, election, public_key=public_key, questions=questions
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
def compute_tally(election_uuid: str, public_key: dict):
    """
    Computes the encrypted tally of an election.
    """
    with SessionLocal() as session:
        election = crud.get_election_by_uuid(uuid=election_uuid, session=session)
        voters_group = crud.get_groups_voters(session=session, election_id=election.id)
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
            pk = PublicKey(**public_key)
            with_votes = len(encrypted_votes) > 0
            tally = election.compute_tally(encrypted_votes, weights, pk)

            crud.create_group_tally(
                session=session,
                election_id=election.id,
                group=group,
                with_votes=with_votes,
                tally_grouped=tally,
            )

        fields = {
            "election_status": ElectionStatusEnum.tally_computed,
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
        tallies = crud.get_tallies_grouped_by_group_and_ordered_by_q_num(session=session, election_id=election.id)
        results = election.combine_decryptions(session=session, tallies=tallies)
        crud.create_result(session=session, election_id=election.id, result=results)
        crud.update_election(session=session, election_id=election.id, fields={"election_status": ElectionStatusEnum.decryptions_combined})


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
