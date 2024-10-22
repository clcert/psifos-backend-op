from app.psifos.model.schemas.schemas import PsifosSchema

from typing import Dict, Any

class ResultsBase(PsifosSchema):
    """
    Schema for creating a results.
    """
    election_id: int
    total_result: Dict[str, Any]
    grouped_result: Dict[str, Any] | None