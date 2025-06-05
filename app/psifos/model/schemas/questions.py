from app.psifos.model.schemas.schemas import PsifosSchema



class QuestionBase(PsifosSchema):
    """
    Schema for creating a question.
    """
    index: int
    type: str
    title: str
    description: str | None
    formal_options: str | None
    max_answers: int
    min_answers: int
    include_informal_options: bool | None
    tally_type: str
    grouped_options: bool | None
    num_of_winners: int | None
