"""
Election result classes for Psifos.

14-04-2022
"""
from app.psifos.crypto.elgamal import ListOfIntegers
from app.database.serialization import SerializableList, SerializableObject


class ResultFactory:
    @staticmethod
    def create(**kwargs):
        tally_type = kwargs.get("tally_type")
        if tally_type == "homomorphic":
            return HomomorphicResult(**kwargs)
        elif tally_type == "mixnet":
            return MixnetResult(**kwargs)
        else:
            return None


class ElectionResultManager(SerializableList):
    def __init__(self, *args) -> None:
        super(ElectionResultManager, self).__init__()
        for result in args:
            self.instances.append(result)


class ElectionResultGroup(SerializableObject):
    def __init__(self, *args, with_votes=True, **kwargs) -> None:
        super(ElectionResultGroup, self).__init__()
        self.group = kwargs.get("group")
        self.result = ElectionResult(*args) if with_votes else args


class ElectionResult(SerializableList):
    def __init__(self, *args) -> None:
        super(ElectionResult, self).__init__()
        for q_res_dict in args:
            self.instances.append(ResultFactory.create(**q_res_dict))


class AbstractResult(SerializableObject):
    def __init__(self, **kwargs) -> None:
        self.tally_type = kwargs["tally_type"]

    def get_ans_results(self):
        return self.ans_results.instances


class HomomorphicResult(AbstractResult):
    def __init__(self, **kwargs) -> None:
        super(HomomorphicResult, self).__init__(**kwargs)
        self.ans_results = ListOfIntegers(*kwargs["ans_results"])


class MixnetResult(AbstractResult):
    def __init__(self, **kwargs) -> None:
        super(MixnetResult, self).__init__(**kwargs)
        self.ans_results = ListOfIntegers(*kwargs["ans_results"])
