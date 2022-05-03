"""
Election question classes for Psifos.

02-05-2022
"""
from psifos.serialization import SerializableList, SerializableObject


class QuestionFactory():
    """
    Implementation of the ''Factory Method'' design
    pattern for election questions. Allows a SerializableList
    (such as the Questions class) to hold different types of 
    objects. The only requirement is to be created by the same
    Factory.
    """

    @staticmethod
    def create(**kwargs):
        q_type = kwargs.get("q_type", None)
        if q_type == "closed_queston":
            return ClosedQuestion(**kwargs)
        elif q_type == "open_question":
            return OpenQuestion(**kwargs)
        else:
            return None


class Questions(SerializableList):
    """
    Subclass of a SerializableList, represents all the questions
    in a Psifos election. The construction of each instance in the 
    list is delegated to a Factory.
    """

    def __init__(self, *args) -> None:
        for q_json in args:
            self.instances.append(QuestionFactory.create(**q_json))


class AbstractQuestion(SerializableObject):
    """
    Holds the common behaviour of an election question.
    """

    def __init__(self, **kwargs) -> None:
        self.q_type: str = kwargs["q_type"]
        self.q_text: str = kwargs["q_text"]
        self.q_description: str = kwargs["q_description"]

        self.total_options: int = kwargs["total_options"]
        self.total_closed_options: int = kwargs["total_closed_options"]
        self.closed_options: list = kwargs["closed_options"]

        self.max_answers: int = kwargs["max_answers"]
        self.min_answers: int = kwargs["min_answers"]

        self.tally_type = "homomorphic"


class OpenQuestion(AbstractQuestion):
    """
    Allows a voter not only to select between closed options, but
    also open options, i.e options written by themself.
    """

    def __init__(self, **kwargs) -> None:
        self.total_open_options: int = kwargs["total_open_options"]
        self.open_option_max_size: int = kwargs["open_option_max_size"]
        super(OpenQuestion, self).__init__(**kwargs)


class ClosedQuestion(AbstractQuestion):
    """
    Allows a voter to select between closed options.
    """

    def __init__(self, **kwargs) -> None:
        super(ClosedQuestion, self).__init__(**kwargs)
