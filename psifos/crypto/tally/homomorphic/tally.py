"""
common workflows and algorithms for Psifos tallies.

Ben Adida
reworked for Psifos: 27-05-2022
"""
import json
from psifos.crypto.elgamal import PublicKey
from psifos.psifos_object.questions import Questions
from psifos.serialization import SerializableObject

import itertools
from ..common.abstract_tally import AbstractTally
from ..common.dlogtable import DLogTable

class HomomorphicTally(AbstractTally):
    """
    Homomorhic tally implementation for closed questions.
    """
    def __init__(self, computed=False, question=None, public_key=None, tally=None, **kwargs) -> None:
        """
        HomomorphicTally constructor, allows the creation of this tally.
        
        If computed==False then questions and public_key cannot be None.
        Else, tally cannot be None
        """
        super(HomomorphicTally, self).__init__(**kwargs)

        if not computed:
            assert (question is not None) and (public_key is not None)
            self.__question = json.dumps(*question)
            self.__public_key = PublicKey(**public_key)
            self.tally = [0 for _ in self.__question['answers']]

        else:
            assert tally is not None
            self.tally = tally
    
    def compute(self, encrypted_answers, weights):
        for vote, weight in zip(encrypted_answers, weights):
            for answer_num in range(self.__question["total_options"]):
                # do the homomorphic addition into the tally
                vote.choices[answer_num].pk = self.public_key
                vote.choices[answer_num].alpha = pow(vote.choices[answer_num].alpha, weight, self.public_key.p)
                vote.choices[answer_num].beta = pow(vote.choices[answer_num].beta, weight, self.public_key.p)
                self.tally[answer_num] = vote.choices[answer_num] * self.tally[answer_num]
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
