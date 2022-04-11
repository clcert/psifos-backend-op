"""
Custom Exceptions for Psifos

11-04-2022
"""

from pyexpat import model


class PsifosModelError(Exception):
    """Base class for Psifos model-related exceptions"""
    pass

class TupleNotFound(PsifosModelError):
    """
    Exception raised when a Model.get_by_field returns nothing

    Attributes:
        model_name -- name of the model
        field_name -- table field used to get the element
        expected_value -- expected value of the field

    """

    def __init__(self, model_name, field_name, expected_value):
        self.model_name = model_name
        super().__init__(message=f"Tuple with field {field_name} = {expected_value} not found")
    
    def __str__(self) -> str:
        return f"PsifosModel {self.model_name} -> {self.message}"
        
