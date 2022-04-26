"""
Abstraction layer for Psifos models.

13-04-2022
"""

from __future__ import annotations
from psifos import db, ma
from typing import Union
from psifos.serialization import SerializableObject

class PsifosModel():
    """
    Abstraction layer for database I/O, allows the developer to:

    (1) Save instances of db.Model with Python objects as column values by
        serializing them.

    (2) Retrieve tuples from the database with their serialized columns 
        instantiated as their corresponding class.
    
    Usage of the methods:
        Let test_schema = TestSchema(), test_model an instance 
        of TestModel and json_data a version of test_model serialized
        as a JSON like string:

        -> To serialize test_model:
            TestModel.to_json(test_schema, test_model)
            >>> json_data

        -> To deserialize json_data:
            TestModel.from_json(test_schema, json_data)
            >>> test_model
        
        (for to_dict/from_dict methods the process is analogous)
        
        -> To execute a query (Ex: TestModel.query.filter_by(id=1)):
            TestModel.execute(test_schema, TestModel.query.filter_by, id=1)

        -> To save test_model:
            TestModel.save(test_schema, test_model)
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
        Serializes a PsifosModel object into a JSON like string.
        """
        return schema.dump(obj)

    @classmethod
    def from_dict(cls, schema: Union[ma.SQLAlchemyAutoSchema, ma.SQLAlchemySchema], json_data: str) -> PsifosModel:
        """
        Deserializes a JSON like string into it's corresponding PsifosModel subclass.
        """
        return schema.load(json_data)
    
    @classmethod
    def execute(cls, schema: Union[ma.SQLAlchemyAutoSchema, ma.SQLAlchemySchema], fun, *args, **kwargs):
        """
        Executes a md.Model function and after that, deserializes the output.
        """
        def __deserialize_model_instance(x):
            return cls.from_json(schema, cls.to_json(schema, x))

        res = fun(*args, **kwargs)
        return [__deserialize_model_instance(x) for x in res]
    
    @classmethod
    def filter_by(cls, schema: Union[ma.SQLAlchemyAutoSchema, ma.SQLAlchemySchema], *args, **kwargs):
        """
        Makes more readable the execution of the filter_by method of SQLAlchemy.
        """
        return cls.execute(schema, cls.query.filter_by, *args, **kwargs)
    
    def save(self) -> None:
        """
        Saves in the database an instance of the model (serializes all columns with a python object as value).
        """
        class_attributes = [attr for attr in dir(self) if not attr.startswith("_")]
        for attr in class_attributes:
            attr_value = getattr(self, attr)
            if isinstance(attr_value, SerializableObject):
                setattr(self, attr, SerializableObject.serialize(attr_value))
        db.session.add(self)
        db.session.commit()
