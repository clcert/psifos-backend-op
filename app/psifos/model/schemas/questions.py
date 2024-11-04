from app.psifos.model.schemas.schemas import PsifosSchema



class QuestionBase(PsifosSchema):
    """
    Schema for creating a question.
    """
    q_num: int
    q_type: str
    q_text: str
    q_description: str | None
    total_options: int
    total_closed_options: int
    closed_options: str | None
    max_answers: int
    min_answers: int
    include_blank_null: bool | None
    tally_type: str
    group_votes: bool | None
    num_of_winners: int | None
