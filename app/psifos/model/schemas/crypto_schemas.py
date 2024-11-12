from app.psifos.model.schemas.schemas import PsifosSchema

class PublicKeyBase(PsifosSchema):
    """
    Schema for creating a public key.
    """
    y: int
    p: int
    g: int
    q: int

    class Config:
        orm_mode = True