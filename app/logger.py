from app.psifos.model import crud
from app.psifos.model.enums import ElectionEventEnum
from app.psifos.utils import tz_now
from app.database import db_handler

import logging

class LogDBHandler(logging.Handler):
    '''
    Customized logging handler that puts logs to the database.
    '''

    _level_to_name = {
        logging.CRITICAL: 'CRITICAL',
        logging.ERROR: 'ERROR',
        logging.WARNING: 'WARNING',
        logging.INFO: 'INFO',
        logging.DEBUG: 'DEBUG',
        logging.NOTSET: 'NOTSET',
    }

    @db_handler.method_with_session
    def emit(self, session, record):
        crud.log_to_db(
            session=session,
            log_level=self._level_to_name[record.levelno],
            log_msg=record.msg,
            created_at=tz_now().strftime("%Y-%m-%d %H:%M:%S"),
            created_by=record.name
        )


class PsifosLogger(logging.Logger):
    """
    Customized logger for psifos own tasks
    """

    def __init__(self, **kwargs) -> None:
        super(PsifosLogger, self).__init__(**kwargs)
        
        self.logger = logging.getLogger(PsifosLogger.__name__)
        log_handler = LogDBHandler()
        self.logger.addHandler(log_handler)


    def log_to_db(self, level, event: ElectionEventEnum, **kwargs):
        log_msg = {"event": event, **kwargs}
        self.logger.log(level, log_msg)
        

psifos_logger = PsifosLogger(name="psifos_logger")