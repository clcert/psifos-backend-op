"""
ElGamal encryption classes for Psifos.

Ben Adida
reworked for Psifos: 14-04-2022
"""
import json

from psifos.crypto.utils import random
from Crypto.Util import number
from Crypto.Hash import SHA1
import logging
from psifos.serialization import SerializableList, SerializableObject


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

    def generate_keypair(self):
        """
        generates a keypair in the setting
        """
        return KeyPair().generate(self.p, self.q, self.g)


class KeyPair(object):
    def __init__(self):
        self.pk = PublicKey()
        self.sk = SecretKey()

    def generate(self, p, q, g):
        """
        Generate an ElGamal keypair
        """
        self.pk.g = int(g)
        self.pk.p = int(p)
        self.pk.q = int(q)

        self.sk.x = random.mpz_lt(q)
        self.pk.y = pow(g, self.sk.x, p)

        self.sk.pk = self.pk
        return self


class PublicKey(SerializableObject):
    def __init__(self, y=None, p=None, g=None, q=None):
        self.y = int(y or 0)
        self.p = int(p or 0)
        self.g = int(g or 0)
        self.q = int(q or 0)

    def encrypt_with_r(self, plaintext, r, encode_message=False):
        """
        expecting plaintext.m to be a big integer
        """
        ciphertext = Ciphertext()
        ciphertext.pk = self

        # make sure m is in the right subgroup
        if encode_message:
            y = plaintext.m + 1
            if pow(y, self.q, self.p) == 1:
                m = y
            else:
                m = -y % self.p
        else:
            m = plaintext.m

        ciphertext.alpha = pow(self.g, r, self.p)
        ciphertext.beta = (m * pow(self.y, r, self.p)) % self.p

        return ciphertext

    def encrypt_return_r(self, plaintext):
        """
        Encrypt a plaintext and return the randomness just generated and used.
        """
        r = random.mpz_lt(self.q)
        ciphertext = self.encrypt_with_r(plaintext, r)

        return [ciphertext, r]

    def encrypt(self, plaintext):
        """
        Encrypt a plaintext, obscure the randomness.
        """
        return self.encrypt_return_r(plaintext)[0]

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

    def verify_sk_proof(self, dlog_proof, challenge_generator=None):
        """
        verify the proof of knowledge of the secret key
        g^response = commitment * y^challenge
        """
        left_side = pow(self.g, dlog_proof.response, self.p)
        right_side = (dlog_proof.commitment * pow(self.y, dlog_proof.challenge, self.p)) % self.p

        expected_challenge = challenge_generator(dlog_proof.commitment) % self.q

        return (left_side == right_side) and (dlog_proof.challenge == expected_challenge)
        

    def clone_with_new_y(self, y):
        params = {
            "p": self.p,
            "q": self.q,
            "g": self.g,
            "y": y
        }
        return PublicKey(**params)



    def validate_pk_params(self):
        # check primality of p
        if not number.isPrime(self.p):
            raise Exception("p is not prime.")

        # check length of p
        if not (number.size(self.p) >= 2048):
            raise Exception("p of insufficient length. Should be 2048 bits or greater.")

        # check primality of q
        if not number.isPrime(self.q):
            raise Exception("q is not prime.")

        # check length of q
        if not (number.size(self.q) >= 256):
            raise Exception("q of insufficient length. Should be 256 bits or greater.")

        if pow(self.g, self.q, self.p) != 1:
            raise Exception("g does not generate subgroup of order q.")

        if not (1 < self.g < self.p - 1):
            raise Exception("g out of range.")

        if not (1 < self.y < self.p - 1):
            raise Exception("y out of range.")

        if pow(self.y, self.q, self.p) != 1:
            raise Exception("g does not generate proper group.")


class SecretKey(SerializableObject):
    def __init__(self, x=None, pk=None):
        self.x = int(x)

        pk_params = pk or {}
        self.pk = PublicKey(**pk_params)
        

    def decryption_factor(self, ciphertext):
        """
        provide the decryption factor, not yet inverted because of needed proof
        """
        return pow(ciphertext.alpha, self.x, self.pk.p)

    def decryption_factor_and_proof(self, ciphertext, challenge_generator=None):
        """
        challenge generator is almost certainly
        fiatshamir_challenge_generator
        """
        if not challenge_generator:
            challenge_generator = fiatshamir_challenge_generator

        dec_factor = self.decryption_factor(ciphertext)

        proof = ZKProof.generate(self.pk.g, ciphertext.alpha, self.x, self.pk.p, self.pk.q, challenge_generator)

        return dec_factor, proof

    def decrypt(self, ciphertext, dec_factor=None, decode_m=False):
        """
        Decrypt a ciphertext. Optional parameter decides whether to encode the message into the proper subgroup.
        """
        if not dec_factor:
            dec_factor = self.decryption_factor(ciphertext)

        m = (number.inverse(dec_factor, self.pk.p) * ciphertext.beta) % self.pk.p

        if decode_m:
            # get m back from the q-order subgroup
            if m < self.pk.q:
                y = m
            else:
                y = -m % self.pk.p

            return Plaintext(y - 1, self.pk)
        else:
            return Plaintext(m, self.pk)

    def prove_decryption(self, ciphertext):
        """
        given g, y, alpha, beta/(encoded m), prove equality of discrete log
        with Chaum Pedersen, and that discrete log is x, the secret key.

        Prover sends a=g^w, b=alpha^w for random w
        Challenge c = sha1(a,b) with and b in decimal form
        Prover sends t = w + xc

        Verifier will check that g^t = a * y^c
        and alpha^t = b * beta/m ^ c
        """

        m = (number.inverse(pow(ciphertext.alpha, self.x, self.pk.p), self.pk.p) * ciphertext.beta) % self.pk.p
        beta_over_m = (ciphertext.beta * number.inverse(m, self.pk.p)) % self.pk.p

        # pick a random w
        w = random.mpz_lt(self.pk.q)
        a = pow(self.pk.g, w, self.pk.p)
        b = pow(ciphertext.alpha, w, self.pk.p)

        c = int(SHA1.new(bytes(str(a) + "," + str(b), 'utf-8')).hexdigest(), 16)

        t = (w + self.x * c) % self.pk.q

        return m, {
            'commitment': {'A': str(a), 'B': str(b)},
            'challenge': str(c),
            'response': str(t)
        }

    def prove_sk(self, challenge_generator):
        """
        Generate a PoK of the secret key
        Prover generates w, a random integer modulo q, and computes commitment = g^w mod p.
        Verifier provides challenge modulo q.
        Prover computes response = w + x*challenge mod q, where x is the secret key.
        """
        w = random.mpz_lt(self.pk.q)
        commitment = pow(self.pk.g, w, self.pk.p)
        challenge = challenge_generator(commitment) % self.pk.q
        response = (w + (self.x * challenge)) % self.pk.q

        return DLogProof(commitment, challenge, response)


class Plaintext(object):
    def __init__(self, m=None, pk=None):
        self.m = m
        self.pk = pk


class Ciphertext(SerializableObject):
    def __init__(self, alpha=None, beta=None, pk=None):
        self.alpha = int(alpha or 0)
        self.beta = int(beta or 0)

        pk_params = pk or {}
        self.pk = PublicKey(**pk_params)

    def __mul__(self, other):
        """
        Homomorphic Multiplication of ciphertexts.
        """
        if isinstance(other, int) and (other == 0 or other == 1):
            return self

        if self.pk != other.pk:
            logging.info(self.pk)
            logging.info(other.pk)
            raise Exception('different PKs!')

        new = Ciphertext()

        new.pk = self.pk
        new.alpha = (self.alpha * other.alpha) % self.pk.p
        new.beta = (self.beta * other.beta) % self.pk.p

        return new

    def reenc_with_r(self, r):
        """
        We would do this homomorphically, except
        that's no good when we do plaintext encoding of 1.
        """
        new_c = Ciphertext()
        new_c.alpha = (self.alpha * pow(self.pk.g, r, self.pk.p)) % self.pk.p
        new_c.beta = (self.beta * pow(self.pk.y, r, self.pk.p)) % self.pk.p
        new_c.pk = self.pk

        return new_c

    def reenc_return_r(self):
        """
        Reencryption with fresh randomness, which is returned.
        """
        r = random.mpz_lt(self.pk.q)
        new_c = self.reenc_with_r(r)
        return [new_c, r]

    def reenc(self):
        """
        Reencryption with fresh randomness, which is kept obscured (unlikely to be useful.)
        """
        return self.reenc_return_r()[0]

    def __eq__(self, other):
        """
        Check for ciphertext equality.
        """
        if other is None:
            return False

        return self.alpha == other.alpha and self.beta == other.beta

    def generate_encryption_proof(self, plaintext, randomness, challenge_generator):
        """
        Generate the disjunctive encryption proof of encryption
        """
        # random W
        w = random.mpz_lt(self.pk.q)

        # build the proof
        proof = ZKProof()

        # compute A=g^w, B=y^w
        proof.commitment.A = pow(self.pk.g, w, self.pk.p)
        proof.commitment.B = pow(self.pk.y, w, self.pk.p)

        # generate challenge
        proof.challenge = challenge_generator(proof.commitment)

        # Compute response = w + randomness * challenge
        proof.response = (w + (randomness * proof.challenge)) % self.pk.q

        return proof

    def simulate_encryption_proof(self, plaintext, challenge=None):
        # generate a random challenge if not provided
        if not challenge:
            challenge = random.mpz_lt(self.pk.q)

        proof = ZKProof()
        proof.challenge = challenge

        # compute beta/plaintext, the completion of the DH tuple
        beta_over_plaintext = (self.beta * number.inverse(plaintext.m, self.pk.p)) % self.pk.p

        # random response, does not even need to depend on the challenge
        proof.response = random.mpz_lt(self.pk.q)

        # now we compute A and B
        proof.commitment.A = (number.inverse(pow(self.alpha, proof.challenge, self.pk.p), self.pk.p)
                                 * pow(self.pk.g, proof.response, self.pk.p)
                                 ) % self.pk.p
        proof.commitment.B = (number.inverse(pow(beta_over_plaintext, proof.challenge, self.pk.p), self.pk.p) * pow(
            self.pk.y, proof.response, self.pk.p)) % self.pk.p

        return proof

    def generate_disjunctive_encryption_proof(self, plaintexts, real_index, randomness, challenge_generator):
        # note how the interface is as such so that the result does not reveal which is the real proof.

        proofs = [None for _ in plaintexts]

        # go through all plaintexts and simulate the ones that must be simulated.
        for p_num in range(len(plaintexts)):
            if p_num != real_index:
                proofs[p_num] = self.simulate_encryption_proof(plaintexts[p_num])

        # the function that generates the challenge
        def real_challenge_generator(commitment):
            # set up the partial real proof so we're ready to get the hash
            proofs[real_index] = ZKProof()
            proofs[real_index].commitment = commitment

            # get the commitments in a list and generate the whole disjunctive challenge
            commitments = [p.commitment for p in proofs]
            disjunctive_challenge = challenge_generator(commitments)

            # now we must subtract all of the other challenges from this challenge.
            real_challenge = disjunctive_challenge
            for p_num in range(len(proofs)):
                if p_num != real_index:
                    real_challenge = real_challenge - proofs[p_num].challenge

            # make sure we mod q, the exponent modulus
            return real_challenge % self.pk.q

        # do the real proof
        real_proof = self.generate_encryption_proof(plaintexts[real_index], randomness, real_challenge_generator)

        # set the real proof
        proofs[real_index] = real_proof

        serialized_proofs = [ZKProof.serialize(proof) for proof in proofs]
        return ZKDisjunctiveProof(*serialized_proofs)

    def verify_encryption_proof(self, plaintext, proof):
        """
        Checks for the DDH tuple g, y, alpha, beta/plaintext.
        (PoK of randomness r.)

        Proof contains commitment = {A, B}, challenge, response
        """
        # check that A, B are in the correct group
        if not (pow(proof.commitment.A, self.pk.q, self.pk.p) == 1 and pow(proof.commitment.B, self.pk.q,
                                                                              self.pk.p) == 1):
            return False

        # check that g^response = A * alpha^challenge
        first_check = (pow(self.pk.g, proof.response, self.pk.p) == (
            (pow(self.alpha, proof.challenge, self.pk.p) * proof.commitment.A) % self.pk.p))

        # check that y^response = B * (beta/m)^challenge
        beta_over_m = (self.beta * number.inverse(plaintext.m, self.pk.p)) % self.pk.p
        second_check = (pow(self.pk.y, proof.response, self.pk.p) == (
            (pow(beta_over_m, proof.challenge, self.pk.p) * proof.commitment.B) % self.pk.p))

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
        return (challenge_generator([p.commitment for p in proof.proofs])) == (sum([p.challenge for p in proof.proofs]) % self.pk.q)

    def decrypt(self, decryption_factors, public_key):
      """
      decrypt a ciphertext given a list of decryption factors (from multiple trustees)
      """
      running_decryption = self.beta
      indices = [f[0] for f in decryption_factors]
      for dec_index, dec_factor in decryption_factors:
        x = pow(dec_factor, lagrange(indices, dec_index, public_key.q), public_key.p)
        running_decryption = (running_decryption * number.inverse(x, public_key.p)) % public_key.p
        
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

    @classmethod
    def generate(cls, little_g, little_h, x, p, q, challenge_generator):
        """
        generate a DDH tuple proof, where challenge generator is
        almost certainly fiatshamir_challenge_generator
        """

        # generate random w
        w = random.mpz_lt(q)

        # create proof instance
        proof = cls()

        # compute A = little_g^w, B=little_h^w
        proof.commitment.A = pow(little_g, w, p)
        proof.commitment.B = pow(little_h, w, p)

        # get challenge
        proof.challenge = challenge_generator(proof.commitment)

        # compute response
        proof.response = (w + (x * proof.challenge)) % q

        # return proof
        return proof

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


class DLogProof(object):
    def __init__(self, commitment, challenge, response):
        self.commitment = int(commitment)
        self.challenge = int(challenge)
        self.response = int(response)


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
