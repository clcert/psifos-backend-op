from pydantic import BaseModel

class UserBase(BaseModel):
    """
    Basic user schema.
    """

    username: str
    password: str
    public_id: str

class UserIn(UserBase):
    """
    Schema for creating a user.
    """
    pass


class UserOut(UserBase):
    """
    Schema for reading/returning User data.
    """
    class Config:
        orm_mode = True