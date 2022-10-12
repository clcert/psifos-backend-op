from app.psifos.model import crud
from app.database import SessionLocal

from app.psifos.model import models, schemas

import logging

class PsifosLogger(logging.Logger):

    """
    Customized logger for pfiso's own tasks
    """

    def __init__(self, session, **kwargs) -> None:

        super(PsifosLogger, self).__init__(**kwargs)

        self.session = session
        self.logger = logging.getLogger(PsifosLogger.__name__)
        self.logger.setLevel(logging.INFO)

    async def voter_info(self, name: str, election: models.Voter):

        """
        Shows information about the voter log on the platform
        
        """

        # Set config psifos info
        logging.basicConfig(format='INFO-PSIFOS: %(asctime)s %(message)s')

        voter = await crud.get_voter_by_name_and_id(session=self.db, voter_name=name, election_id=election.id)
        status_logging = "successfully" if voter else "incorrectly"
        self.logger.info(f"Voter {name} authenticated {status_logging} in {election.short_name}")

    def trustee_info(self, name: str, trustee: models.Trustee, election: models.Election):

        """
        Shows information about the trustee log on the platform
        
        """

        # Set config psifos info
        logging.basicConfig(format='INFO-PSIFOS: %(asctime)s %(message)s')

        status_logging = "successfully" if trustee else "incorrectly"
        self.logger.info(f"Trustee {name} authenticated {status_logging} in {election.short_name}")

    def save_db(self):

        pass


#with SessionLocal() as session:
#    psifos_logger = PsifosLogger(session=session, name="psifosLogger")