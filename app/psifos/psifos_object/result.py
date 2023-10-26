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

class GenericResults(SerializableObject):
    def __init__(self, result) -> None:
        super(GenericResults, self).__init__()
        self.ans_results = ListOfIntegers(*result["ans_results"])

class ResultListTotal(SerializableList):
    def __init__(self, *args) -> None:
        super(ResultListTotal, self).__init__()
        for result in args:
            self.instances.append(GenericResults(result))


class ResultListGrouped(SerializableList):
    def __init__(self, *args) -> None:
        super(ResultListGrouped, self).__init__()
        for result in args:
            self.instances.append(result)


class ElectionResultManager(SerializableObject):
    def __init__(self, **kwargs) -> None:
        super(ElectionResultManager, self).__init__()
        results_total = kwargs.get('results_total')
        results_grouped = kwargs.get('results_grouped')
        self.results_total = ResultListTotal(*results_total)
        self.results_grouped = ResultListGrouped(*results_grouped)


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
