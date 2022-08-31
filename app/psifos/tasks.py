"""
Async celery tasks for Psifos (psifos module)

lib: celery
broker: redis
gui: flower

31-08-2022
"""


from app.celery_worker import celery

@celery.task(name="process_castvote")
def process_cast_vote(*args, **kwargs):
    """
    Verifies if a cast_vote is valid, if so then
    it stores it in the database.
    """
    pass


@celery.task(name="compute_tally")
def compute_tally(*args, **kwargs):
    """
    Computes the encrypted tally of an election.
    """
    pass


@celery.task(name="decrypt_tally")
def decrypt_tally(*args, **kwargs):
    """
    Decrypts the encrypted tally of an election by
    combining the partial decryptions of the trustees.
    """
    pass


@celery.task(name="upload_voters")
def upload_voters(*args, **kwargs):
    """
    Handles the upload of a voter file.
    """
    pass


