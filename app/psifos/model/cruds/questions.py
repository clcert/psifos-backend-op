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
    db_question = await get_question_by_q_num(session, election_id, question_id)
    for key, value in question.items():
        setattr(db_question, key, value)
    await session.commit()
    return db_question


async def get_questions_by_election_id(session: Session | AsyncSession, election_id: int):
    return await session.execute(select(AbstractQuestion).filter(AbstractQuestion.election_id == election_id))

async def get_question_by_q_num(session: Session | AsyncSession, election_id: int, q_num: int):
    db_question = await session.execute(select(AbstractQuestion).filter(AbstractQuestion.election_id == election_id, AbstractQuestion.q_num == q_num))
    return db_question.scalars().first()


async def delete_question(session: Session | AsyncSession, question_id: int):
    await session.execute(delete(AbstractQuestion).filter(AbstractQuestion.id == question_id))
    await session.commit()
    return question_id