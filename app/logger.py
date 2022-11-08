import logging
import json

from app.psifos.model import crud
from app.psifos.model.enums import ElectionEventEnum
from app.psifos.utils import tz_now
from app.database import db_handler

class ElectionLogger(object):
    """
    Customized logger for psifos own tasks
    """

    _level_to_name = {
        logging.CRITICAL: 'CRITICAL',
        logging.ERROR: 'ERROR',
        logging.WARNING: 'WARNING',
        logging.INFO: 'INFO',
        logging.DEBUG: 'DEBUG',
        logging.NOTSET: 'NOTSET',
    }

    @db_handler.method_with_session
    async def _log_to_db(self, session, level, election_id, event: ElectionEventEnum, **kwargs):
        await crud.log_to_db(
            session=session,
            log_level=self._level_to_name[level],
            election_id=election_id,
            event=event,
            event_params=json.dumps(kwargs),
            created_at=tz_now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        
    
    async def critical(self, election_id, event: ElectionEventEnum, **kwargs):
        await self._log_to_db(logging.CRITICAL, election_id, event, **kwargs)

        
    async def error(self, election_id, event: ElectionEventEnum, **kwargs):
        await self._log_to_db(logging.ERROR, election_id, event, **kwargs)

        
    async def warning(self, election_id, event: ElectionEventEnum, **kwargs):
        await self._log_to_db(logging.WARNING, election_id, event, **kwargs)

        
    async def info(self, election_id, event: ElectionEventEnum, **kwargs):
        await self._log_to_db(logging.INFO, election_id, event, **kwargs)
    
        
    async def debug(self, election_id, event: ElectionEventEnum, **kwargs):
        await self._log_to_db(logging.DEBUG, election_id, event, **kwargs)
    
        
    async def notset(self, election_id, event: ElectionEventEnum, **kwargs):
        await self._log_to_db(logging.NOTSET, election_id, event, **kwargs)

        
psifos_logger = ElectionLogger()
