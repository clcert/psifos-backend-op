"""
Election question classes for Psifos.

02-05-2022
"""
from app.database.serialization import SerializableList, SerializableObject


class QuestionFactory():
    """
    Implementation of the ''Factory Method'' design
    pattern for election questions. Allows a SerializableList
    (such as the Questions class) to hold different types of 
    objects.
    """

    @staticmethod
    def create(**kwargs):
        q_type_list = {
            "closed_question": ClosedQuestion,
            "mixnet_question": MixnetQuestion,
            "stvnc_question": STVNCQuestion,
        }
        q_type = kwargs.get("q_type", None)
        if q_type in q_type_list.keys():
            return q_type_list[q_type](**kwargs)
        return None


class Questions(SerializableList):
    """
    Subclass of a SerializableList, represents all the questions
    in a Psifos election. The construction of each instance in the 
    list is delegated to a Factory.
    """

    def __init__(self, *args) -> None:
        super(Questions, self).__init__()
        for q_dict in args:
            self.instances.append(QuestionFactory.create(**q_dict))

    def check_tally_type(self, tally_type: str):
        for q in self.instances:
            if q.tally_type != tally_type:
                return False
        return True


class AbstractQuestion(SerializableObject):
    """
    Holds the common behaviour of an election question.
    """

    def __init__(self, **kwargs) -> None:
        self.q_type: str = kwargs["q_type"]
        self.q_text: str = kwargs["q_text"]
        self.q_description: str = kwargs["q_description"]

        self.total_options: int = int(kwargs["total_options"])
        self.total_closed_options: int = int(kwargs["total_closed_options"])
        self.closed_options: list = kwargs["closed_options"]

        self.max_answers: int = int(kwargs["max_answers"])
        self.min_answers: int = int(kwargs["min_answers"])

        self.include_blank_null: str = str(kwargs["include_blank_null"])
        self.excluding_groups: str = str(kwargs["excluding_groups"])

class ClosedQuestion(AbstractQuestion):
    """
    Allows a voter to select between closed options.
    """

    def __init__(self, **kwargs) -> None:
        super(ClosedQuestion, self).__init__(**kwargs)
        self.tally_type = "homomorphic"


class MixnetQuestion(AbstractQuestion):
    """
    Allows a voter to select between mixnet options.
    """

    def __init__(self, **kwargs) -> None:
        super(MixnetQuestion, self).__init__(**kwargs)
        self.tally_type = "mixnet"
        self.group_votes: str = str(kwargs["group_votes"])

class STVNCQuestion(AbstractQuestion):
    """
    Allows a voter to select a permutation of options.
    Is the no coersion case.
    """

    def __init__(self, **kwargs) -> None:
        super(STVNCQuestion, self).__init__(**kwargs)
        self.tally_type = "stvnc"
        self.num_of_winners: int = int(kwargs["num_of_winners"])
