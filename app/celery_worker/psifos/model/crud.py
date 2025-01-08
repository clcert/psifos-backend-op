from app.psifos.model import models
from app.psifos.model.decryptions import HomomorphicDecryption, MixnetDecryption
from app.psifos.model.tally import TallyTypeEnum
from app.psifos.model.results import Results
from app.psifos.model.questions import AbstractQuestion
from app.psifos.model.schemas import schemas
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from sqlalchemy.orm import selectinload, defer
from collections import defaultdict


ELECTION_QUERY_OPTIONS = [

    selectinload(models.Election.trustees),
    selectinload(models.Election.sharedpoints),
    selectinload(models.Election.audited_ballots),
    selectinload(models.Election.questions),
    selectinload(models.Election.result),
]

def get_election_by_uuid(session: Session, uuid: str):
    query = select(models.Election).where(models.Election.uuid == uuid).options(
        *ELECTION_QUERY_OPTIONS
    )
    result = session.execute(query)
    return result.scalars().first()

def get_election_by_short_name(session: Session, short_name: str):
    query = select(models.Election).where(models.Election.short_name == short_name)
    result = session.execute(query)
    return result.scalars().first()

def get_election_params_by_short_name(session: Session, short_name: str, params: list):
    query = select(*params).where(models.Election.short_name == short_name)
    result = session.execute(query)
    return result.first()

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

def voter_has_valid_vote(session: Session, voter_id: int, election_id: int):
    query = select(models.Voter.username).join(
        models.CastVote, models.CastVote.voter_id == models.Voter.id).where(
        models.Voter.id == voter_id,
        models.Voter.election_id == election_id,
        models.CastVote.is_valid
    )
    result = session.execute(query)
    return result.scalars().first()

def get_voter_by_login_id_and_election_id(session: Session, username: int, election_id: int):
    query = select(models.Voter).where(
        models.Voter.username == username,
        models.Voter.election_id == election_id
    )
    result = session.execute(query)
    return result.scalars().first()

def create_voter(session: Session, election_id: int, voter: schemas.VoterIn):

    try:
        db_voter = models.Voter(election_id=election_id, **voter.dict())
        session.add(db_voter)
        session.commit()
        session.refresh(db_voter)

        # db_cast_vote = models.CastVote(voter_id=db_voter.id)
        # session.add(db_cast_vote)
        # session.commit()
        # session.refresh(db_cast_vote)
        return db_voter #, db_cast_vote

    except Exception as e:
        session.rollback()
        return None
    
def create_voters(session: Session, voters: list[models.Voter]):
    try:
        session.add_all(voters)
        session.commit()
        return len(voters)

    except Exception as e:
        session.rollback()
        return None

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

def get_public_key_by_election_id(session: Session, election_id: int):
    query = select(models.PublicKey).where(models.PublicKey.election_id == election_id)
    result = session.execute(query)
    return result.scalars().first()

def get_questions_by_election_id(session: Session, election_id: int):
    query = select(AbstractQuestion).where(AbstractQuestion.election_id == election_id)
    result = session.execute(query)
    return result.scalars().all()

# Tally
def get_tally_by_election_id(session: Session, election_id: int):
    query = select(models.Tally).where(
        models.Tally.election_id == election_id,
    )
    result = session.execute(query)
    return result.scalars().all()

def get_tally_by_election_id_and_group(session: Session, election_id: int, group: str):
    query = select(models.Tally).where(
        models.Tally.election_id == election_id,
        models.Tally.group == group
    )
    result = session.execute(query)
    return result.scalars().all()

def get_tallies_grouped_by_group_and_ordered_by_q_num(session: Session, election_id: int):
    # Consulta para obtener todos los Tallys, ordenados por group y luego por q_num
    query = (
        select(models.Tally).join(
        models.AbstractQuestion, models.Tally.question_id == models.AbstractQuestion.id).where(
        models.AbstractQuestion.election_id == election_id).order_by(
        models.Tally.group, models.AbstractQuestion.index)  # Ordena por grupo y luego por q_num
    )
    result = session.execute(query)
    tallies = result.scalars().all()

    # Agrupar los Tallys por group usando defaultdict
    grouped_tallies = defaultdict(list)
    for tally in tallies:
        grouped_tallies[tally.group].append(tally)

    # Convertir el defaultdict a una lista de listas (arreglo de arreglos)
    return list(grouped_tallies.values())

def create_group_tally(session: Session, election_id: int, group: str, with_votes: bool, tally_grouped: list) -> list:
    """
    Creates a group tally for a given election and group.
    """
    for item in tally_grouped:
        db_tally = models.Tally(
            group=group,
            with_votes=with_votes,
            tally_type=item.tally_type,
            computed=item.computed,
            num_tallied=item.num_tallied,
            encrypted_tally=item.encrypted_tally,
            question_id=item.question.id,
        )
        session.rollback()  
        session.add(db_tally)
        session.commit()
    return tally_grouped
# Decryption

def get_homomorphic_decryption_by_trustee_id(session: Session, trustee_crypto_id: int, q_num: int, group: str):
    query = select(HomomorphicDecryption).join(
        models.AbstractQuestion, models.HomomorphicDecryption.question_id == models.AbstractQuestion.id
    ).where(
        models.HomomorphicDecryption.trustee_crypto_id == trustee_crypto_id,
        models.AbstractQuestion.index == q_num,
        models.HomomorphicDecryption.group == group
    )
    result = session.execute(query)
    return result.scalars().first()

def get_mixnet_decryption_by_trustee_id(session: Session, trustee_crypto_id: int, q_num: int, group: str):
    query = select(MixnetDecryption).where(
        models.MixnetDecryption.trustee_crypto_id == trustee_crypto_id,
        models.AbstractQuestion.index == q_num,
        models.MixnetDecryption.group == group
    )
    result = session.execute(query)
    return result.scalars().first()

def get_decryptions_by_trustee_id(session: Session, trustee_crypto_id: int, q_num: int, group: str = ""):
    h_decryption = get_homomorphic_decryption_by_trustee_id(session, trustee_crypto_id, q_num, group)
    if h_decryption:
        return h_decryption
    
    m_decryption = get_mixnet_decryption_by_trustee_id(session, trustee_crypto_id, q_num, group)
    return m_decryption