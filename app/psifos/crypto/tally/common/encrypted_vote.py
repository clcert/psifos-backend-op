"""
Encrypted answer for Psifos vote.

27-05-2022
"""

from app.database.serialization import SerializableList, SerializableObject
from .encrypted_answer.enc_ans_factory import EncryptedAnswerFactory

import logging


class ListOfEncryptedAnswers(SerializableList):
    def __init__(self, *answers) -> None:
        super(ListOfEncryptedAnswers, self).__init__()
        for ans_dict in answers:
            self.instances.append(EncryptedAnswerFactory.create(**ans_dict))

class EncryptedVote(SerializableObject):
    """
    An encrypted ballot
    """

    def __init__(self, short_name, answers):
        self.short_name : str = short_name
        self.answers : ListOfEncryptedAnswers = ListOfEncryptedAnswers(*answers)

    def verify(self, election, public_key, questions):
        # correct number of answers
        # noinspection PyUnresolvedReferences
        n_answers = len(self.answers.instances)
        n_questions = len(questions)
        if n_answers != n_questions:
            logging.error(f"Incorrect number of answers ({n_answers}) vs questions ({n_questions})")
            return False


        # check ID
        # noinspection PyUnresolvedReferences
        our_short_name = self.short_name if isinstance(self.short_name, str) else self.short_name.decode()
        actual_short_name = election.short_name if isinstance(election.short_name, str) else election.short_name.decode()
        if our_short_name != actual_short_name:
            logging.error(f"Incorrect short_name {our_short_name} vs {actual_short_name} ")
            return False

        # check proofs on all of answers
        for question_num in range(len(questions)):
            ea = self.answers.instances[question_num]
            q = questions[question_num]
            if not ea.verify(pk=public_key, min_ptxt=q.min_answers, max_ptxt=q.max_answers):
                return False

        return True
