from app.psifos.model import crud
from app.database import SessionLocal

from app.psifos.model import models, schemas

import logging

class PsifosLogger(logging.Logger):

    """
    Customized logger for pfiso's own tasks
    """

    def __init__(self, **kwargs) -> None:

        super(PsifosLogger, self).__init__(**kwargs)

        self.logger = logging.getLogger(PsifosLogger.__name__)
        self.logger.setLevel(logging.INFO)

        ch = logging.StreamHandler()

        formatter = logging.Formatter('INFO-PSIFOS: %(asctime)s %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    async def voter_info(self, name: str, election: models.Voter):

        """
        Shows information about the voter log on the platform
        
        """

        voter = await crud.get_voter_by_name_and_id(session=self.db, voter_name=name, election_id=election.id)
        status_logging = "successfully" if voter else "incorrectly"
        self.logger.info(f"Voter {name} authenticated {status_logging} in {election.short_name}")

    def trustee_info(self, name: str, trustee: models.Trustee, election: models.Election):

        """
        Shows information about the trustee log on the platform
        
        """

        status_logging = "successfully" if trustee else "incorrectly"
        self.logger.info(f"Trustee {name} authenticated {status_logging} in {election.short_name}")

    def save_db(self):

        pass



psifos_logger = PsifosLogger(name="psifosLogger")