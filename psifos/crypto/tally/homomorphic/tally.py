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
    def __init__(self, tally=None, **kwargs) -> None:
        """
        HomomorphicTally constructor, allows the creation of this tally.
        
        If computed==False then questions cannot be None.
        Else, tally cannot be None
        """
        super(HomomorphicTally, self).__init__(**kwargs)

        if not self.computed:
            self.tally = [0] * self.question.total_options

        else:
            self.tally = tally
    
    def compute(self, encrypted_answers, weights):
        self.computed = True
        for vote, weight in zip(encrypted_answers, weights):
            for answer_num in range(len(self.tally)):
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
        question_factors = []
        question_proofs = []

        for answer_num in range(len(self.tally)):
            # do decryption and proof of it
            dec_factor, proof = sk.decryption_factor_and_proof(self.tally[answer_num])

            # look up appropriate discrete log
            # this is the string conversion
            question_factors.append(dec_factor)
            question_proofs.append(proof)

        return question_factors, question_proofs

    def verify_decryption_proofs(self, decryption_factors, decryption_proofs, public_key, challenge_generator):
        """
        decryption_factors is a list of lists of dec factors
        decryption_proofs are the corresponding proofs
        public_key is, of course, the public key of the trustee
        """

        # go through each one
        for a_num, answer_tally in enumerate(self.tally):
            proof = decryption_proofs[a_num]

            # check that g, alpha, y, dec_factor is a DH tuple
            cond = proof.verify(
                public_key.g,
                answer_tally.alpha,
                public_key.y,
                int(decryption_factors[a_num]),
                public_key.p,
                public_key.q,
                challenge_generator
            )
            if not cond:
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

        q_result = []

        for a_num, a in enumerate(self.tally):
            last_raw_value = None
            # generate al subsets of size t+1 and compare values between each iteration
            for subset_factor_list in itertools.combinations(
                [(di, df[a_num]) for di, df in decryption_factors],
                    t + 1):
                raw_value = a.decrypt(subset_factor_list, public_key)
                if raw_value is None:
                    raise Exception("Error computing decryption: None returned")
                if last_raw_value is not None and raw_value != last_raw_value:
                    raise Exception("Not all decryptions agree!")
                last_raw_value = raw_value
            q_result.append(raw_value)

        return [dlog_table.lookup(result) for result in q_result]
