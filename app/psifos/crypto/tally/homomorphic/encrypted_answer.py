from app.psifos.crypto.elgamal import ZKDisjunctiveProof
from app.psifos.crypto.elgamal import ListOfZKDisjunctiveProofs
from app.psifos.crypto.tally.common.encrypted_answer.abstract_enc_ans import AbstractEncryptedAnswer
from app.psifos.crypto.elgamal import Plaintext, disjunctive_challenge_generator


class EncryptedClosedAnswer(AbstractEncryptedAnswer):
    """
    An encrypted closed answer to a single election question.
    """
    def __init__(self, **kwargs):
        super(EncryptedClosedAnswer, self).__init__(**kwargs)
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
            choice._pk = pk
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