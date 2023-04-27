"""
ElGamal encryption classes for Psifos.

Ben Adida
reworked for Psifos: 14-04-2022
"""

from app.database.serialization import SerializableList, SerializableObject
from Crypto.Util import number
from Crypto.Hash import SHA1


def lagrange(indices, index, modulus):
    result = 1
    for i in indices:
        if i == index: continue
        result = (result * i * number.inverse(i - index, modulus)) % modulus
    return result
class ElGamal(SerializableObject):
    def __init__(self, p=None, q=None, g=None, l=None, t=None):
        self.p = int(p)
        self.q = int(q)
        self.g = int(g)
        self.l = l
        self.t = t

class PublicKey(SerializableObject):
    def __init__(self, y=None, p=None, g=None, q=None):
        self.y = int(y or 0)
        self.p = int(p or 0)
        self.g = int(g or 0)
        self.q = int(q or 0)

    def __mul__(self, other):
        if other == 0 or other == 1:
            return self

        # check p and q
        if self.p != other.p or self.q != other.q or self.g != other.g:
            raise Exception("incompatible public keys")

        params = {
            "p": self.p,
            "q": self.q,
            "g": self.g,
            "y": (self.y * other.y) % self.p,
        }
        return PublicKey(**params)

    def clone_with_new_y(self, y):
        params = {
            "p": self.p,
            "q": self.q,
            "g": self.g,
            "y": y
        }
        return PublicKey(**params)

class Plaintext(object):
    def __init__(self, m=None, pk=None):
        self.m = m
        self._pk = pk

class Ciphertext(SerializableObject):
    def __init__(self, alpha=None, beta=None, pk=None):
        self.alpha = int(alpha or 0)
        self.beta = int(beta or 0)
        self._pk = pk

    def __mul__(self, other):
        """
        Homomorphic Multiplication of ciphertexts.
        """
        if isinstance(other, int) and (other == 0 or other == 1):
            return self

        if self._pk is None or other._pk is None:
            raise Exception('missing PK in a Ciphertext')
        
        if self._pk != other._pk:
            raise Exception('different PKs!')

        new = Ciphertext()
        new._pk = self._pk
        new.alpha = (self.alpha * other.alpha) % self._pk.p
        new.beta = (self.beta * other.beta) % self._pk.p

        return new

    def __eq__(self, other):
        """
        Check for ciphertext equality.
        """
        if other is None:
            return False

        return self.alpha == other.alpha and self.beta == other.beta

    def verify_encryption_proof(self, plaintext, proof):
        """
        Checks for the DDH tuple g, y, alpha, beta/plaintext.
        (PoK of randomness r.)

        Proof contains commitment = {A, B}, challenge, response
        """
        # check that A, B are in the correct group
        if not (pow(proof.commitment.A, self._pk.q, self._pk.p) == 1 and pow(proof.commitment.B, self._pk.q,
                                                                              self._pk.p) == 1):
            return False

        # check that g^response = A * alpha^challenge
        first_check = (pow(self._pk.g, proof.response, self._pk.p) == (
            (pow(self.alpha, proof.challenge, self._pk.p) * proof.commitment.A) % self._pk.p))

        # check that y^response = B * (beta/m)^challenge
        beta_over_m = (self.beta * number.inverse(plaintext.m, self._pk.p)) % self._pk.p
        second_check = (pow(self._pk.y, proof.response, self._pk.p) == (
            (pow(beta_over_m, proof.challenge, self._pk.p) * proof.commitment.B) % self._pk.p))

        # print "1,2: %s %s " % (first_check, second_check)
        return first_check and second_check

    def verify_disjunctive_encryption_proof(self, plaintexts, proof, challenge_generator):
        """
        plaintexts and proofs are all lists of equal length, with matching.

        overall_challenge is what all of the challenges combined should yield.
        """
        if len(plaintexts) != len(proof.proofs):
            print("bad number of proofs (expected %s, found %s)" % (len(plaintexts), len(proof.proofs)))
            return False

        for i in range(len(plaintexts)):
            # if a proof fails, stop right there
            if not self.verify_encryption_proof(plaintexts[i], proof.proofs[i]):
                print("bad proof %s, %s, %s" % (i, plaintexts[i], proof.proofs[i]))
                return False

        # logging.info("made it past the two encryption proofs")

        # check the overall challenge
        return (challenge_generator([p.commitment for p in proof.proofs])) == (sum([p.challenge for p in proof.proofs]) % self._pk.q)

    def decrypt(self, decryption_factors, public_key, decode_m=False):
      """
      decrypt a ciphertext given a list of decryption factors (from multiple trustees)
      """
      running_decryption = self.beta
      indices = [f[0] for f in decryption_factors]
      for dec_index, dec_factor in decryption_factors:
        x = pow(dec_factor, lagrange(indices, dec_index, public_key.q), public_key.p)
        running_decryption = (running_decryption * number.inverse(x, public_key.p)) % public_key.p

      if decode_m:
        if running_decryption < public_key.q:
          y = running_decryption
        else:
          y = -running_decryption % public_key.p
        return y - 1
      else:
        return running_decryption

    def check_group_membership(self, pk):
        """
        checks to see if an ElGamal element belongs to the group in the pk
        """
        if not (1 < self.alpha < pk.p - 1):
            return False

        elif not (1 < self.beta < pk.p - 1):
            return False

        elif pow(self.alpha, pk.q, pk.p) != 1:
            return False

        elif pow(self.beta, pk.q, pk.p) != 1:
            return False

        else:
            return True

class ListOfCipherTexts(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfCipherTexts, self).__init__()
        for ctxt_dict in args:
            self.instances.append(Ciphertext(**ctxt_dict))


class ZKProof(SerializableObject):
    def __init__(self, challenge=None, response=None, commitment=None):
        self.challenge = int(challenge or 0)
        self.response = int(response or 0)
        commitment_params = commitment or {}
        self.commitment = ZKProofCommitment(**commitment_params)

    def verify(self, little_g=None, little_h=None, big_g=None, big_h=None, p=None, challenge_generator=None):
        """
        Verify a DH tuple proof
        """
        # check that little_g^response = A * big_g^challenge
        first_check = (pow(little_g, self.response, p) == ((pow(big_g, self.challenge, p) * self.commitment.A) % p))
        
        # check that little_h^response = B * big_h^challenge
        second_check = (pow(little_h, self.response, p) == ((pow(big_h, self.challenge, p) * self.commitment.B) % p))

        # check the challenge?
        third_check = True
        
        if challenge_generator:
            third_check = (self.challenge == challenge_generator(self.commitment))

        return (first_check and second_check and third_check)

class ListOfIntegers(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfIntegers, self).__init__()
        for value in args:
            self.instances.append(int(value))

class ListOfVotes(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfVotes, self).__init__()
        for value in args:
            self.instances.append(ListOfIntegers(*value))

class ListOfZKProofs(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfZKProofs, self).__init__()
        for proof_dict in args:
            self.instances.append(ZKProof(**proof_dict))

class ZKProofCommitment(SerializableObject):
    def __init__(self, A=None, B=None) -> None:
        self.A = int(A or 0)
        self.B = int(B or 0)


class ZKDisjunctiveProof(SerializableList):
    def __init__(self, *args):
        super(ZKDisjunctiveProof, self).__init__()
        for p_dict in args:
            self.instances.append(ZKProof(**p_dict))
        
    @property
    def proofs(self):
        return self.instances

class ListOfZKDisjunctiveProofs(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfZKDisjunctiveProofs, self).__init__()
        for zkdp_list in args:
            self.instances.append(ZKDisjunctiveProof(*zkdp_list))


def disjunctive_challenge_generator(commitments):
    array_to_hash = []
    for commitment in commitments:
        array_to_hash.append(str(commitment.A))
        array_to_hash.append(str(commitment.B))

    string_to_hash = ",".join(array_to_hash)
    return int(SHA1.new(bytes(string_to_hash, 'utf-8')).hexdigest(), 16)


# a challenge generator for Fiat-Shamir with A,B commitment
def fiatshamir_challenge_generator(commitment):
    return disjunctive_challenge_generator([commitment])


def DLog_challenge_generator(commitment):
    string_to_hash = str(commitment)
    return int(SHA1.new(bytes(string_to_hash, 'utf-8')).hexdigest(), 16)
