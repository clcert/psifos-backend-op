from wtforms import fields

import json
from typing import List

class JSONField(fields.TextAreaField):
    def _value(self) -> str:
        if self.raw_data:
            return self.raw_data[0]
        
        if 'instances' in vars(self.data):
            data_array = []
            for data in vars(self.data)['instances']:
                data_array.append(vars(data))
            
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
