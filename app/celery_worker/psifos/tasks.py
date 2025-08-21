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
    voters_login_type: str,
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
            models.Election.public_key_id,
            models.Election.short_name
        ]

        election = crud.get_election_params_by_short_name(short_name=election_short_name, session=session, params=query_params)
        questions = crud.get_questions_by_election_id(election_id=election.id, session=session)
        public_key = crud.get_public_key(session=session, id=election.public_key_id)
        if voters_login_type == ElectionLoginTypeEnum.close_p:
            voter_id = kwargs.get("voter_id")
            voter = crud.get_voter_by_voter_id(voter_id=voter_id, session=session)
        else:
            username = kwargs.get("username")
            voter = crud.get_voter_by_login_id_and_election_id(
                session=session, username=username, election_id=election.id
            )
            if not voter:
                voter_in = schemas.VoterIn(
                    username=username,
                    name=username,
                    username_election_id=f"{username}_{election.id}",
                    weight_init=1,
                    weight_end=1,
                    group="",
                )
                voter = crud.create_voter(
                    session=session,
                    election_id=election.id,
                    voter=voter_in,
                )

        enc_vote_data = psifos_utils.from_json(serialized_encrypted_vote)
        encrypted_vote = EncryptedVote(**enc_vote_data)
        is_valid, cast_vote_fields = voter.process_cast_vote(
            encrypted_vote, election, public_key=public_key, questions=questions
        )
        cast_vote = crud.update_or_create_cast_vote(
            session=session,
            voter_id=voter.id,
            fields=cast_vote_fields,
        )

    if is_valid:
        return is_valid, cast_vote.encrypted_ballot_hash

    return is_valid, None


@celery.task(name="compute_tally")
def compute_tally(short_name: str, public_key: dict):
    """
    Computes the encrypted tally of an election.
    """
    with SessionLocal() as session:
        election = crud.get_election_by_short_name(
            short_name=short_name,
            session=session,
        )
        
        # Obtenemos todos los grupos con sus votantes en una sola consulta
        groups_with_voters = crud.get_groups_with_voters(session, election.id)
        
        # Procesamiento paralelo por grupo (todos los datos ya están en memoria)
        for group, voters in groups_with_voters:
            _process_group_voters(
                session=session,
                election=election,
                public_key=public_key,
                group=group,
                voters=voters
            )
        
        # Actualización final
        crud.update_election(
            session=session,
            election_id=election.id,
            fields={"status": ElectionStatusEnum.tally_computed}
        )

def _process_group_voters(session, election, public_key, group, voters):
    """Procesa todos los votantes de un grupo en una sola operación"""
    # Filtrado de votantes válidos
    not_null_voters = [
        v for v in voters 
        if crud.voter_has_valid_vote(session=session, voter_id=v.id, election_id=election.id)
    ]
    
    # Procesamiento de votos cifrados
    encrypted_votes = [
        EncryptedVote(**(psifos_utils.from_json(EncryptedVote.serialize(v.cast_vote.encrypted_ballot))))
        for v in not_null_voters
    ]
    
    # Cálculo del tally
    weights = [v.weight_end for v in not_null_voters]
    pk = PublicKey(**public_key)
    with_votes = len(encrypted_votes) > 0
    
    tally = election.compute_tally(
        encrypted_votes=encrypted_votes,
        weights=weights,
        public_key=pk,
        with_votes=with_votes,
        group=group
    )
    
    # Registro en base de datos
    crud.create_group_tally(
        session=session,
        election_id=election.id,
        group=group,
        with_votes=with_votes,
        tally_grouped=tally,
    )

@celery.task(name="combine_decryptions", ignore_result=True)
def combine_decryptions(short_name: str):
    """
    Combines the partial decryptions of the trustees and releases
    the election results.
    """
    with SessionLocal() as session:
        election = crud.get_election_by_short_name(session=session, short_name=short_name)
        tallies = crud.get_tallies_grouped_by_group_and_ordered_by_q_num(session=session, election_id=election.id)
        results = election.combine_decryptions(session=session, tallies=tallies)
        crud.create_result(session=session, election_id=election.id, result=results)
        crud.update_election(session=session, election_id=election.id, fields={"status": ElectionStatusEnum.decryptions_combined})


@celery.task(name="upload_voters")
def upload_voters(election_id: str, voter_file_content: str):
    """
    Handles the upload of a voter file.
    """
    with SessionLocal() as session:
        election = crud.get_election_by_id(election_id=election_id, session=session)
        login_voters = set()
        voters = []
        try:
            grouped = election.grouped_voters
            buffer = StringIO(voter_file_content)
            csv_reader = csv.reader(buffer, delimiter=",")
            k = 0  # voter counter
            n = 0  # total voters
            for voter in csv_reader:
                n += 1
                add_group = len(voter) > 3 and grouped
                v_in = {
                    "username": voter[0],
                    "name": voter[1],
                    "weight_init": voter[2],
                    "weight_end": voter[2],
                    "username_election_id": f"{voter[0]}_{election.id}",
                    "group": voter[3] if add_group else ""
                }
                v_in = schemas.VoterIn(**v_in)
                if v_in.username_election_id not in login_voters:
                    login_voters.add(v_in.username_election_id)
                    voters.append(models.Voter(election_id=election_id, **v_in.dict()))
                    k += 1
            crud.create_voters(session=session, voters=voters)
        except Exception as e:
            return False, 0, 0

    return True, k, n

@celery.task(name="process_public_vote")
def process_public_vote(election_id: str, public_vote: dict) -> bool:
    """
    Checks if the public vote is valid.
    """
    with SessionLocal() as session:

        questions = crud.get_questions_by_election_id(election_id=election_id, session=session)
        public_vote = models.Vote(**public_vote)
        public_vote.is_valid = public_vote.verify(questions=questions)
        public_vote.vote_hash = uuid.uuid4()
        if not public_vote.is_valid:
            return public_vote
        
        crud.save_public_vote(
            session=session,
            public_vote=public_vote
        )
        return public_vote.is_valid, public_vote.vote_hash
