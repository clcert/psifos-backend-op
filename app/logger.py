import logging
import json

from app.psifos.model import crud
from app.psifos.model.enums import ElectionEventEnum
from app.psifos.utils import tz_now
from app.database import db_handler

import sys
from pathlib import Path
from loguru import logger

class InterceptHandler(logging.Handler):
    loglevel_mapping = {
        50: 'CRITICAL',
        40: 'ERROR',
        30: 'WARNING',
        20: 'INFO',
        10: 'DEBUG',
        0: 'NOTSET',
    }

    def emit(self, record):
        try:
            level = logger.level(record.levelname).name
        except AttributeError:
            level = self.loglevel_mapping[record.levelno]

        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        log = logger.bind(request_id='app')
        log.opt(
            depth=depth,
            exception=record.exc_info
        ).log(level,record.getMessage())


class CustomizeLogger:

    @classmethod
    def make_logger(cls,config_path: Path):

        config = cls.load_logging_config(config_path)
        logging_config = config.get('logger')

        logger = cls.customize_logging(
            logging_config.get('path') ,
            level=logging_config.get('level'),
            retention=logging_config.get('retention'),
            rotation=logging_config.get('rotation'),
            format=logging_config.get('format')
        )
        return logger

    @classmethod
    def customize_logging(cls,
            filepath: Path,
            level: str,
            rotation: str,
            retention: str,
            format: str
    ):

        logger.remove()
        logger.level("PSIFOS", no=35, color="<red>", icon="")
        logger.add(
            sys.stdout,
            enqueue=True,
            backtrace=True,
            level=level.upper(),
            format=format
        )
        logger.add(
            str(filepath),
            rotation=rotation,
            retention=retention,
            enqueue=True,
            backtrace=True,
            level=level.upper(),
            format=format
        )
        logging.basicConfig(handlers=[InterceptHandler()], level=0)
        logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]
        for _log in ['uvicorn',
                     'uvicorn.error',
                     'fastapi'
                     ]:
            _logger = logging.getLogger(_log)
            _logger.handlers = [InterceptHandler()]

        return logger.bind(request_id=None, method=None) 


    @classmethod
    def load_logging_config(cls, config_path):
        config = None
        with open(config_path) as config_file:
            config = json.load(config_file)
        return config


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

logger_config_path = Path(__file__).with_name("logger_config.json")
logger = CustomizeLogger.make_logger(logger_config_path)
