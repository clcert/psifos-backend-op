from app.psifos.model.schemas.questions import QuestionBase
from app.psifos.model.questions import AbstractQuestion
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from app.database import db_handler

from sqlalchemy import select, update, delete



async def create_question(session: Session | AsyncSession, election_id: int, question: QuestionBase):

    db_question = AbstractQuestion(election_id=election_id, **question)
    db_handler.add(session, db_question)
    await db_handler.commit(session)
    return db_question

async def edit_question(session: Session | AsyncSession, election_id, question_id: int, question: QuestionBase):
    db_question = await get_question_by_index(session, election_id, question_id)
    question_type = question.get("type", None)
    db_question.tally_type = db_question.TALLY_TYPE_MAP.get(question_type, "CLOSED")
    for key, value in question.items():
        setattr(db_question, key, value)
    await session.commit()
    return db_question


async def get_questions_by_election_id(session: Session | AsyncSession, election_id: int):
    db_questions = await session.execute(select(AbstractQuestion).filter(AbstractQuestion.election_id == election_id))
    return db_questions.scalars().all()

async def get_question_by_index(session: Session | AsyncSession, election_id: int, index: int):
    db_question = await session.execute(select(AbstractQuestion).filter(AbstractQuestion.election_id == election_id, AbstractQuestion.index == index))
    return db_question.scalars().first()


async def delete_question(session: Session | AsyncSession, question_id: int):
    await session.execute(delete(AbstractQuestion).filter(AbstractQuestion.id == question_id))
    await session.commit()
    return question_id

async def delete_questions_by_election_id_index(session: Session | AsyncSession, election_id: int, index: int):
    await session.execute(delete(AbstractQuestion).filter(AbstractQuestion.election_id == election_id, AbstractQuestion.index == index))
    await session.commit()
    return index