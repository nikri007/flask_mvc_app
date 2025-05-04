from marshmallow import Schema, fields
import json

class ContactSchema(Schema):
    id = fields.Int(dump_only=True)
    user_id = fields.Int(dump_only=True)
    first_name = fields.Str(required=True)
    last_name = fields.Str(required=True)
    address = fields.Str(required=False)
    company = fields.Str(required=False)
    phone_numbers = fields.Method('get_phone_numbers', deserialize='load_phone_numbers')
    created_at = fields.DateTime(dump_only=True)
    
    def get_phone_numbers(self, obj):
        if isinstance(obj.phone_numbers, str):
            return json.loads(obj.phone_numbers)
        return obj.phone_numbers
    
    def load_phone_numbers(self, value):
        return json.dumps(value)