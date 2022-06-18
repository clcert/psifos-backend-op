"""
Abstraction layer for Psifos models.

13-04-2022
"""

from __future__ import annotations
from psifos import db, ma
from typing import Union


class PsifosModel():
    """
    
    """
    @classmethod
    def to_json(cls, schema: Union[ma.SQLAlchemyAutoSchema, ma.SQLAlchemySchema], obj: PsifosModel) -> str:
        """
        Serializes a PsifosModel object into a JSON like string.
        """
        return schema.dumps(obj)

    @classmethod
    def from_json(cls, schema: Union[ma.SQLAlchemyAutoSchema, ma.SQLAlchemySchema], json_data: str) -> PsifosModel:
        """
        Deserializes a JSON like string into it's corresponding PsifosModel subclass.
        """
        return schema.loads(json_data)

    @classmethod
    def to_dict(cls, schema: Union[ma.SQLAlchemyAutoSchema, ma.SQLAlchemySchema], obj: PsifosModel) -> str:
        """
        Serializes a PsifosModel object into a dict.
        """
        return schema.dump(obj)

    @classmethod
    def from_dict(cls, schema: Union[ma.SQLAlchemyAutoSchema, ma.SQLAlchemySchema], json_data: str) -> PsifosModel:
        """
        Deserializes a dict into it's corresponding PsifosModel subclass.
        """
        return schema.load(json_data)

    @classmethod
    def execute(cls, fun, *args, **kwargs):
        """
        """
        return list(fun(*args, **kwargs))

    @classmethod
    def filter_by(cls, *args, **kwargs):
        """
        Makes more readable the execution of the filter_by method of SQLAlchemy.
        """
        return cls.execute(cls.query.filter_by, *args, **kwargs)
    
    @staticmethod
    def add(target) -> None:
        """
        Adds changes to the session, must be commited!
        """
        db.session.add(target)
        db.session.flush()

    @staticmethod
    def delete(target) -> None:
        """
        Deletes an instance from the database, must be commited!
        """
        db.session.delete(target)

    @staticmethod
    def commit() -> None:
        """
        Commits all changes an deletions done to the model.
        """
        db.session.commit()