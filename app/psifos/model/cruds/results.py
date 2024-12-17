from app.psifos.model.schemas.results import ResultsBase
from app.psifos.model.results import Results
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from app.database import db_handler

from sqlalchemy import select


async def create_result(session: Session | AsyncSession, election_id: int, result: ResultsBase) -> Results:

    db_result = Results(election_id=election_id, **result)
    db_handler.add(session, db_result)
    await db_handler.commit(session)
    return db_result

async def get_result_by_election_id(session: Session | AsyncSession, election_id: int) -> Results:
    stmt = select(Results).filter(Results.election_id == election_id)
    result = await session.execute(stmt)
    return result.scalars().first()
