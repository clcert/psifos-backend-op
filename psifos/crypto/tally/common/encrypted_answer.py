"""
Encrypted answer for Psifos vote.

27-05-2022
"""

from psifos.crypto.elgamal import Ciphertext, ListOfCipherTexts, ListOfZKDisjunctiveProofs, Plaintext, ZKDisjunctiveProof, disjunctive_challenge_generator
from psifos.serialization import SerializableObject

class EncryptedAnswerFactory(SerializableObject):
    def create(**kwargs):
        q_type = kwargs.get("enc_ans_type", None)
        if q_type == "encrypted_closed_answer":
            return EncryptedClosedAnswer(**kwargs)
        elif q_type == "encrypted_open_answer":
            return EncryptedOpenAnswer(**kwargs)
        else:
            return None


class AbstractEncryptedAnswer(SerializableObject):
    def __init__(self, **kwargs) -> None:
        self.enc_ans_type = kwargs["enc_ans_type"]

        self.choices : ListOfCipherTexts = ListOfCipherTexts(*kwargs["choices"])
        self.individual_proofs : ListOfZKDisjunctiveProofs = ListOfZKDisjunctiveProofs(*kwargs["individual_proofs"])
        self.overall_proof : ZKDisjunctiveProof = ZKDisjunctiveProof(*kwargs["overall_proof"])
        
    @classmethod
    def generate_plaintexts(cls, pk, min_ptxt=0, max_ptxt=1): 
        plaintexts = []
        running_product = 1

        # run the product up to the min
        for i in range(max_ptxt + 1):
            # if we're in the range, add it to the array
            if i >= min_ptxt:
                plaintexts.append(Plaintext(running_product, pk))

            # next value in running product
            running_product = (running_product * pk.g) % pk.p

        return plaintexts


    def verify(self, pk, min_ptxt=0, max_ptxt=1):
        possible_plaintexts = self.generate_plaintexts(pk)
        homomorphic_sum = 0

        for choice_num in range(len(self.choices.instances)):
            choice = self.choices.instances[choice_num]
            choice.pk = pk
            individual_proof = self.individual_proofs.instances[choice_num]

            # verify that elements belong to the proper group
            check_group = choice.check_group_membership(pk)
            if not check_group:
                return False
            
            # verify the proof on the encryption of that choice
            verify_disjunctive_enc_proof = choice.verify_disjunctive_encryption_proof(
                possible_plaintexts,
                individual_proof,
                disjunctive_challenge_generator
            )
            if not verify_disjunctive_enc_proof:
                return False

            # compute homomorphic sum if needed
            if max_ptxt is not None:
                homomorphic_sum = choice * homomorphic_sum

        if max_ptxt is not None:
            # determine possible plaintexts for the sum
            sum_possible_plaintexts = self.generate_plaintexts(pk, min_ptxt=min_ptxt, max_ptxt=max_ptxt)

            # verify the sum
            return homomorphic_sum.verify_disjunctive_encryption_proof(
                sum_possible_plaintexts,
                self.overall_proof,
                disjunctive_challenge_generator
            )
        else:
            # approval voting, no need for overall proof verification
            return True

    def get_choices(self):
        return self.choices.instances
class EncryptedOpenAnswer(AbstractEncryptedAnswer):
    """
    An encrypted open answer to a single election question.
    """
    def __init__(self, **kwargs) -> None:
        self.open_answer : Ciphertext = Ciphertext(**kwargs["open_answer"])
        super(EncryptedOpenAnswer, self).__init__(**kwargs)


class EncryptedClosedAnswer(AbstractEncryptedAnswer):
    """
    An encrypted closed answer to a single election question.
    """
    def __init__(self, **kwargs):
        super(EncryptedClosedAnswer, self).__init__(**kwargs)




    '''
    TODO: Adapt fromElectionAndAnswer method to the new structure of EncryptedAnswers.


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
            randomness[answer_num] = random.mpz_lt(pk.q)
            choices[answer_num] = pk.encrypt_with_r(plaintexts[plaintext_index], randomness[answer_num])

            # generate proof
            individual_proofs[answer_num] = choices[answer_num].generate_disjunctive_encryption_proof(
                plaintexts, plaintext_index, randomness[answer_num], disjunctive_challenge_generator)
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
                sum_plaintexts, num_selected_answers - min_answers, randomness_sum, disjunctive_challenge_generator)
        else:
            # approval voting
            overall_proof = None

        return cls(choices, individual_proofs, overall_proof, randomness, answer_indexes)
    '''