from __future__ import annotations
import json

class SerializableObject(object):
    """ 
    This class is an abstraction layer for serialization
    and deserialization of an object.
    """
    @classmethod
    def serialize(cls, obj : SerializableObject) -> str:
        """ 
        Serializes an object to a JSON like string. 
        """
        if isinstance(obj, str):
            return obj

        return json.dumps(obj.__dict__)
    
    @classmethod
    def deserialize(cls, json_data : str) -> SerializableObject:
        """ 
        Deserializes a JSON like string to a specific 
        class instance. 
        """
        return cls(**json.loads(json_data))
