from wtforms import fields
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote

import json
from typing import List

class JSONField(fields.TextAreaField):
    def _value(self) -> str:
        if self.raw_data:
            return self.raw_data[0]
        
        class_serializer = {
            'vote': EncryptedVote
        }
        
        if self.id in class_serializer:
            return str(class_serializer[self.id].serialize(obj = self.data))
            
        if 'instances' in vars(self.data):
            data_array = []
            for data in vars(self.data)['instances']:
                data_array.append(data if type(data) is dict else vars(data))
            
            return str(json.dumps(data_array, ensure_ascii=False))

        elif self.data:
            data = vars(self.data)
            return str(json.dumps(data, ensure_ascii=False))
        else:
            return "{}"

    def process_formdata(self, valuelist: List[str]) -> None:
        if valuelist:
            value = valuelist[0]

            # allow saving blank field as None
            if not value:
                self.data = None
                return

            try:
                self.data = value
            except ValueError:
                raise ValueError(self.gettext("Invalid JSON"))
