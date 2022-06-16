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

    def __init__(self, election_uuid, election_hash, answers):
        self.election_uuid : str = election_uuid
        self.election_hash : str = election_hash
        self.answers : ListOfEncryptedAnswers = ListOfEncryptedAnswers(*answers)

    def verify(self, election):
        # correct number of answers
        # noinspection PyUnresolvedReferences
        n_answers = len(self.encrypted_answers) if self.encrypted_answers is not None else 0
        n_questions = len(election.questions) if election.questions is not None else 0
        if n_answers != n_questions:
            logging.error(f"Incorrect number of answers ({n_answers}) vs questions ({n_questions})")
            return False

        # check hash
        # noinspection PyUnresolvedReferences
        our_election_hash = self.election_hash if isinstance(self.election_hash, str) else self.election_hash.decode()
        actual_election_hash = election.hash if isinstance(election.hash, str) else election.hash.decode()
        if our_election_hash != actual_election_hash:
            logging.error(f"Incorrect election_hash {our_election_hash} vs {actual_election_hash} ")
            return False

        # check ID
        # noinspection PyUnresolvedReferences
        our_election_uuid = self.election_uuid if isinstance(self.election_uuid, str) else self.election_uuid.decode()
        actual_election_uuid = election.uuid if isinstance(election.uuid, str) else election.uuid.decode()
        if our_election_uuid != actual_election_uuid:
            logging.error(f"Incorrect election_uuid {our_election_uuid} vs {actual_election_uuid} ")
            return False

        # check proofs on all of answers
        for question_num in range(len(election.questions)):
            ea = self.encrypted_answers[question_num]

            question = election.questions[question_num]
            min_answers = 0
            if 'min' in question:
                min_answers = question['min']

            if not ea.verify(election.public_key, min=min_answers, max=question['max']):
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