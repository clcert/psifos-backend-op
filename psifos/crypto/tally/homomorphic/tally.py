"""
common workflows and algorithms for Psifos tallies.

Ben Adida
reworked for Psifos: 27-05-2022
"""
from psifos.serialization import SerializableObject

import itertools
from ..common.abstract_tally import AbstractTally
from ..common.dlogtable import DLogTable

class HomomorphicTally(AbstractTally):
    """
    Homomorhic tally implementation for closed questions.
    """
    def __init__(self, *args, **kwargs) -> None:
        super(HomomorphicTally, self).__init__(*args, **kwargs)


class Tally(SerializableObject):
    """
    A running homomorphic tally
    """

    def __init__(self, *args, **kwargs):
        super(Tally, self).__init__()

        election = kwargs.get('election', None)
        self.tally = None
        self.num_tallied = 0

        if election:
            self.init_election(election)
            self.tally = [[0 for a in q['answers']] for q in self.questions]
        else:
            self.questions = None
            self.public_key = None
            self.tally = None

    def init_election(self, election):
        """
        given the election, initialize some params
        """
        self.election = election
        self.questions = election.questions
        self.public_key = election.public_key

    def add_vote_batch(self, encrypted_votes, verify_p=True):
        """
        Add a batch of votes. Eventually, this will be optimized to do an aggregate proof verification
        rather than a whole proof verif for each vote.
        """
        for vote in encrypted_votes:
            self.add_vote(vote, verify_p)

    def add_vote(self, encrypted_vote, weight=1, verify_p=True):
        # do we verify?
        if verify_p:
            if not encrypted_vote.verify(self.election):
                raise Exception('Bad Vote')

        # for each question
        for question_num in range(len(self.questions)):
            question = self.questions[question_num]
            answers = question['answers']

            # for each possible answer to each question
            for answer_num in range(len(answers)):
                # do the homomorphic addition into the tally
                enc_vote_choice = encrypted_vote.encrypted_answers[question_num].choices[answer_num]
                enc_vote_choice.pk = self.public_key
                encrypted_vote.encrypted_answers[question_num].choices[answer_num].alpha = pow(
                    encrypted_vote.encrypted_answers[question_num].choices[answer_num].alpha, weight, self.public_key.p)
                encrypted_vote.encrypted_answers[question_num].choices[answer_num].beta = pow(
                    encrypted_vote.encrypted_answers[question_num].choices[answer_num].beta, weight, self.public_key.p)
                self.tally[question_num][answer_num] = encrypted_vote.encrypted_answers[question_num].choices[answer_num] * self.tally[question_num][answer_num]

        self.num_tallied += 1

    def decryption_factors_and_proofs(self, sk):
        """
        returns an array of decryption factors and a corresponding array of decryption proofs.
        makes the decryption factors into strings, for general Helios / JS compatibility.
        """
        # for all choices of all questions (double list comprehension)
        decryption_factors = []
        decryption_proof = []

        for question_num, question in enumerate(self.questions):
            answers = question['answers']
            question_factors = []
            question_proof = []

            for answer_num, answer in enumerate(answers):
                # do decryption and proof of it
                dec_factor, proof = sk.decryption_factor_and_proof(self.tally[question_num][answer_num])

                # look up appropriate discrete log
                # this is the string conversion
                question_factors.append(dec_factor)
                question_proof.append(proof)

            decryption_factors.append(question_factors)
            decryption_proof.append(question_proof)

        return decryption_factors, decryption_proof

    def decrypt_and_prove(self, sk, discrete_logs=None):
        """
        returns an array of tallies and a corresponding array of decryption proofs.
        """

        # who's keeping track of discrete logs?
        if not discrete_logs:
            discrete_logs = self.discrete_logs

        # for all choices of all questions (double list comprehension)
        decrypted_tally = []
        decryption_proof = []

        for question_num in range(len(self.questions)):
            question = self.questions[question_num]
            answers = question['answers']
            question_tally = []
            question_proof = []

            for answer_num in range(len(answers)):
                # do decryption and proof of it
                plaintext, proof = sk.prove_decryption(self.tally[question_num][answer_num])

                # look up appropriate discrete log
                question_tally.append(discrete_logs[plaintext])
                question_proof.append(proof)

            decrypted_tally.append(question_tally)
            decryption_proof.append(question_proof)

        return decrypted_tally, decryption_proof

    def verify_decryption_proofs(self, decryption_factors, decryption_proofs, public_key, challenge_generator):
        """
        decryption_factors is a list of lists of dec factors
        decryption_proofs are the corresponding proofs
        public_key is, of course, the public key of the trustee
        """

        # go through each one
        for q_num, q in enumerate(self.tally):
            for a_num, answer_tally in enumerate(q):
                # parse the proof
                #proof = elgamal.ZKProof.fromJSONDict(decryption_proofs[q_num][a_num])
                proof = decryption_proofs[q_num][a_num]

                # check that g, alpha, y, dec_factor is a DH tuple
                if not proof.verify(public_key.g, answer_tally.alpha, public_key.y,
                                    int(decryption_factors[q_num][a_num]),
                                    public_key.p, public_key.q, challenge_generator):
                    return False

        return True

    def decrypt_from_factors(self, decryption_factors, public_key, t, max_weight=1):
        """
        decrypt a tally given decryption factors

        The decryption factors are a list of decryption factor sets, for each trustee.
        Each decryption factor set is a list of lists of decryption factors (questions/answers).
        """

        # pre-compute a dlog table
        dlog_table = DLogTable(base=public_key.g, modulus=public_key.p)
        dlog_table.precompute(self.num_tallied * max_weight)

        result = []

        # go through each one
        for q_num, q in enumerate(self.tally):
            q_result = []

            for a_num, a in enumerate(q):
                last_raw_value = None
                # generate al subsets of size t+1 and compare values between each iteration
                for subset_factor_list in itertools.combinations(
                    [(di, df[q_num][a_num]) for di, df in decryption_factors],
                        t + 1):
                    raw_value = a.decrypt(subset_factor_list, public_key)
                    if raw_value is None:
                        raise Exception("Error computing decryption: None returned")
                    if last_raw_value is not None and raw_value != last_raw_value:
                        raise Exception("Not all decryptions agree!")
                    last_raw_value = raw_value
                q_result.append(raw_value)
            result.append(q_result)
        final_results = [[dlog_table.lookup(result) for result in q_result] for q_result in result]
        return final_results
