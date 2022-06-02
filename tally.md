# Explicacion Tally Helios


1. El campo `encrypted_tally` de una eleccion es generado en la view compute_tally. El proceso de creacion consiste en iniciar la instancia del Tally y luego cargarle los encrypted_votes.

    ```python
    class Election():
        ...

        def compute_tally(self):
            tally = self.init_tally()
            for voter in self.voter_set.exclude(vote=None):
                tally.add_vote(
                    voter.vote,
                    voter.weight,
                    verify_p=False
                )

                self.encrypted_tally = tally
                ...
    ```


2. El metodo `init_tally()` simplemente llama al constructor de `Tally` y le pasa la eleccion como parametro, el constructor lo que hace es:

    ```python
    def __init__(self, *args, **kwargs):  
        self.num_tallied = 0    
        self.election = election
        self.questions = election.questions
        self.public_key = election.public_key # genereada al freezear
        self.tally = [[0 for a in q['answers']] for q in self.questions]
        ...
    ```
    Lo que hace el constructor es cargar en el Tally variables de la eleccion y crear el camop `tally` el cual corresponde a un arreglo de arreglos de ceros. Hay tantos arreglos como preguntas hayan y en cada uno tantos ceros como respuestas hayan para su pregunta correspondiente.

3. El metodo `add_vote()` recibe un `EncryptedVote` y el peso del votante. Un voto encriptado corresponde a una lista de `EncryptedAnswer`, para entender bien que hace el metodo veamos que es la implementacion de una respuesta encriptada:

    ```python
    class EncryptedAnswer(LDObject):
        ...
        STRUCTURED_FIELDS = {
            'choices': arrayOf('core/EGCiphertext'),
            'individual_proofs': arrayOf('core/EGZKDisjunctiveProof'),
            'overall_proof': 'core/EGZKDisjunctiveProof',
            }
    ```
    La implementacion de `add_vote` es: 

    ```python
    def add_vote(self, encrypted_vote, weight=1, verify_p=True):
        if verify_p:
            if not encrypted_vote.verify(self.election):
                raise Exception('Bad Vote')

        for question_num in range(len(self.questions)):
            question = self.questions[question_num]
            answers = question['answers']
            
            for answer_num in range(len(answers)):
                enc_vote_choice = encrypted_vote.encrypted_answers[question_num].choices[answer_num]

                enc_vote_choice.pk = self.public_key

                encrypted_vote.encrypted_answers[question_num].choices[answer_num].alpha = pow(encrypted_vote.encrypted_answers[question_num].choices[answer_num].alpha, weight, self.public_key.p)

                encrypted_vote.encrypted_answers[question_num].choices[answer_num].beta = pow(encrypted_vote.encrypted_answers[question_num].choices[answer_num].beta, weight, self.public_key.p)

                self.tally[question_num][answer_num] = encrypted_vote.encrypted_answers[question_num].choices[answer_num] * 
                self.tally[question_num][answer_num]

        self.num_tallied += 1
    ```
