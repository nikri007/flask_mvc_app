from marshmallow import Schema, fields, ValidationError, validates_schema, validate
import json

class UserRegistrationSchema(Schema):
    first_name = fields.Str(required=True)
    last_name = fields.Str(required=True)
    email = fields.Email(required=True)
    password = fields.Str(required=True)
    confirm_password = fields.Str(required=True)
    date_of_birth = fields.Date(required=True)
    gender = fields.Str(required=True, validate=validate.OneOf(
        ['Male', 'Female', 'Other'],
        error='Gender must be one of: Male, Female, Other'
    ))
    phone_numbers = fields.List(fields.Str(), required=False)
    address = fields.Str(required=True)
    profile_picture = fields.Str(required=False)
    
    @validates_schema
    def validate_passwords(self, data, **kwargs):
        if data.get('password') != data.get('confirm_password'):
            raise ValidationError('Passwords do not match', 'confirm_password')

class UserLoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True)

class UserProfileSchema(Schema):
    id = fields.Int(dump_only=True)
    first_name = fields.Str()
    last_name = fields.Str()
    email = fields.Email()
    date_of_birth = fields.Date()
    gender = fields.Str()
    phone_numbers = fields.Method('get_phone_numbers')
    address = fields.Str()
    profile_picture = fields.Str()
    created_at = fields.DateTime(dump_only=True)
    
    def get_phone_numbers(self, obj):
        if isinstance(obj.phone_numbers, str):
            return json.loads(obj.phone_numbers)
        return obj.phone_numbers