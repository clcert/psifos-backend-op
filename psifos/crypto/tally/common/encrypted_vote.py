"""
Encrypted answer for Psifos vote.

27-05-2022
"""

from psifos.serialization import SerializableList, SerializableObject
from .encrypted_answer import EncryptedAnswerFactory

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

    def __init__(self, election_uuid, answers):
        self.election_uuid : str = election_uuid
        self.answers : ListOfEncryptedAnswers = ListOfEncryptedAnswers(*answers)

    def verify(self, election):
        # correct number of answers
        # noinspection PyUnresolvedReferences
        n_answers = len(self.answers.instances)
        n_questions = len(election.questions.instances)
        if n_answers != n_questions:
            logging.error(f"Incorrect number of answers ({n_answers}) vs questions ({n_questions})")
            return False


        # check ID
        # noinspection PyUnresolvedReferences
        our_election_uuid = self.election_uuid if isinstance(self.election_uuid, str) else self.election_uuid.decode()
        actual_election_uuid = election.uuid if isinstance(election.uuid, str) else election.uuid.decode()
        if our_election_uuid != actual_election_uuid:
            logging.error(f"Incorrect election_uuid {our_election_uuid} vs {actual_election_uuid} ")
            return False

        # check proofs on all of answers
        for question_num in range(len(election.questions.instances)):
            ea = self.answers.instances[question_num]

            q = election.questions.instances[question_num]

            if not ea.verify(election.public_key, min_ptxt=q.min_answers, max_ptxt=q.max_answers):
                return False

        return True

    '''
    This method is only used to instantiate EncryptedAnswers when a client
    is not able to encrypt his own answers at them computer. Due to the recent
    change in how EncryptedAnswers are handled (i.e. now we have two classes, 
    EncryptedClosedAnswer & EncryptedOpenAnswer), a re-thinking of this method is 
    needed, hopefully using the EncryptedAnswerFactory as it's the "new way" of 
    creating Encrypted Answers
    
    TODO: Adapt fromElectionAndAnswers method to the new structure of EncryptedAnswers.


    @classmethod
    def fromElectionAndAnswers(cls, election, answers):
        pk = election.public_key

        # each answer is an index into the answer array
        encrypted_answers = [
            EncryptedAnswer.fromElectionAndAnswer(election, answer_num, answers[answer_num])
            for answer_num in range(len(answers))]
        return_val = cls()
        return_val.encrypted_answers = encrypted_answers
        return_val.election_hash = election.hash
        return_val.election_uuid = election.uuid

        return return_val
    '''