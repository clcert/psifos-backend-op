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
        q_type = kwargs.get("q_type", None)
        if q_type == "closed_question":
            return ClosedQuestion(**kwargs)
        elif q_type == "open_question":
            return OpenQuestion(**kwargs)
        elif q_type == "mixnet_question":
            return MixnetQuestion(**kwargs)
        else:
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


class OpenQuestion(AbstractQuestion):
    """
    Allows a voter not only to select between closed options, but
    also open options, i.e options written by themself.
    """

    def __init__(self, **kwargs) -> None:
        self.total_open_options: int = int(kwargs["total_open_options"])
        self.open_option_max_size: int = int(kwargs["open_option_max_size"])
        super(OpenQuestion, self).__init__(**kwargs)


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
