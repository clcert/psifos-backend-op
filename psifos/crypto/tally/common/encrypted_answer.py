"""
Encrypted answer for Psifos vote.

27-05-2022
"""

from psifos.serialization import SerializableObject
from psifos.crypto import elgamal

class EncryptedAnswerFactory(SerializableObject):
    pass

class EncryptedAnswer(SerializableObject):
    """
    An encrypted answer to a single election question
    """

    def __init__(
            self, choices=None, individual_proofs=None, overall_proof=None, randomness=None, answer=None,
            open_answer=None):
        self.choices = choices
        self.individual_proofs = individual_proofs
        self.overall_proof = overall_proof
        self.randomness = randomness
        self.answer = answer
        self.open_answer = open_answer

    @classmethod
    def generate_plaintexts(cls, pk, min=0, max=1):
        plaintexts = []
        running_product = 1

        # run the product up to the min
        for i in range(max+1):
            # if we're in the range, add it to the array
            if i >= min:
                plaintexts.append(elgamal.Plaintext(running_product, pk))

            # next value in running product
            running_product = (running_product * pk.g) % pk.p

        return plaintexts

    def verify_plaintexts_and_randomness(self, pk):
        """
        this applies only if the explicit answers and randomness factors are given
        we do not verify the proofs here, that is the verify() method
        """
        if not hasattr(self, 'answer'):
            return False

        for choice_num in range(len(self.choices)):
            choice = self.choices[choice_num]
            choice.pk = pk

            # redo the encryption
            # WORK HERE (paste from below encryption)

        return False

    def verify(self, pk, min=0, max=1):
        possible_plaintexts = self.generate_plaintexts(pk)
        homomorphic_sum = 0

        for choice_num in range(len(self.choices)):
            choice = self.choices[choice_num]
            choice.pk = pk
            individual_proof = self.individual_proofs[choice_num]

            # verify the proof on the encryption of that choice
            if not choice.verify_disjunctive_encryption_proof(
                    possible_plaintexts, individual_proof, elgamal.disjunctive_challenge_generator):
                #      if not choice.verify_disjunctive_encryption_proof(possible_plaintexts, individual_proof, elgamal.disjunctive_challenge_generator):
                return False

            # compute homomorphic sum if needed
            if max is not None:
                homomorphic_sum = choice * homomorphic_sum

        if max is not None:
            # determine possible plaintexts for the sum
            sum_possible_plaintexts = self.generate_plaintexts(pk, min=min, max=max)

            # verify the sum
            return homomorphic_sum.verify_disjunctive_encryption_proof(
                sum_possible_plaintexts, self.overall_proof, elgamal.disjunctive_challenge_generator)
        else:
            # approval voting, no need for overall proof verification
            return True

    @classmethod
    def fromElectionAndAnswer(cls, election, question_num, answer_indexes):
        """
        Given an election, a question number, and a list of answers to that question
        in the form of an array of 0-based indexes into the answer array,
        produce an EncryptedAnswer that works.
        """
        question = election.questions[question_num]
        answers = question['answers']
        pk = election.public_key

        # initialize choices, individual proofs, randomness and overall proof
        choices = [None for a in range(len(answers))]
        individual_proofs = [None for a in range(len(answers))]
        overall_proof = None
        randomness = [None for a in range(len(answers))]

        # possible plaintexts [0, 1]
        plaintexts = cls.generate_plaintexts(pk)

        # keep track of number of options selected.
        num_selected_answers = 0

        # homomorphic sum of all
        homomorphic_sum = 0
        randomness_sum = 0

        # min and max for number of answers, useful later
        min_answers = 0
        if 'min' in question:
            min_answers = question['min']
        max_answers = question['max']

        # go through each possible answer and encrypt either a g^0 or a g^1.
        for answer_num in range(len(answers)):
            plaintext_index = 0

            # assuming a list of answers
            if answer_num in answer_indexes:
                plaintext_index = 1
                num_selected_answers += 1

            # randomness and encryption
            randomness[answer_num] = elgamal.random.mpz_lt(pk.q)
            choices[answer_num] = pk.encrypt_with_r(plaintexts[plaintext_index], randomness[answer_num])

            # generate proof
            individual_proofs[answer_num] = choices[answer_num].generate_disjunctive_encryption_proof(
                plaintexts, plaintext_index, randomness[answer_num], elgamal.disjunctive_challenge_generator)
            # sum things up homomorphically if needed
            if max_answers is not None:
                homomorphic_sum = choices[answer_num] * homomorphic_sum
                randomness_sum = (randomness_sum + randomness[answer_num]) % pk.q

        # prove that the sum is 0 or 1 (can be "blank vote" for this answer)
        # num_selected_answers is 0 or 1, which is the index into the plaintext that is actually encoded

        if num_selected_answers < min_answers:
            raise Exception("Need to select at least %s answer(s)" % min_answers)

        if max_answers is not None:
            sum_plaintexts = cls.generate_plaintexts(pk, min=min_answers, max=max_answers)

            # need to subtract the min from the offset
            overall_proof = homomorphic_sum.generate_disjunctive_encryption_proof(
                sum_plaintexts, num_selected_answers - min_answers, randomness_sum, elgamal.disjunctive_challenge_generator)
        else:
            # approval voting
            overall_proof = None

        return cls(choices, individual_proofs, overall_proof, randomness, answer_indexes)