from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import db
from app.models.user import User
from app.schemas.user import UserRegistrationSchema, UserLoginSchema, UserProfileSchema
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

# Validation schemas
registration_schema = UserRegistrationSchema()
login_schema = UserLoginSchema()
profile_schema = UserProfileSchema()

@auth_bp.route('/register', methods=['POST'])
def register():
    # Handle form data and file upload
    if request.content_type and 'multipart/form-data' in request.content_type:
        data = request.form.to_dict()
        
        # Parse phone numbers from form
        if 'phone_numbers' in data:
            try:
                data['phone_numbers'] = json.loads(data['phone_numbers'])
            except:
                data['phone_numbers'] = []
        
        # Handle profile picture upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename:
                filename = secure_filename(file.filename)
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                data['profile_picture'] = filename
    else:
        data = request.get_json()
    
    # Always convert date_of_birth to a Python date object
    if 'date_of_birth' in data and isinstance(data['date_of_birth'], str):
        try:
            data['date_of_birth'] = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
    
    # Validate input data
    errors = registration_schema.validate(data)
    if errors:
        return jsonify({'error': errors}), 400
    
    # Check if user already exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    # Create new user
    user = User(
        first_name=data['first_name'],
        last_name=data['last_name'],
        email=data['email'],
        date_of_birth=data['date_of_birth'],
        gender=data['gender'],
        phone_numbers=json.dumps(data.get('phone_numbers', [])),
        address=data['address'],
        profile_picture=data.get('profile_picture')
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    # Generate token
    access_token = create_access_token(identity=user.id)
    
    return jsonify({
        'message': 'User registered successfully',
        'user': profile_schema.dump(user),
        'token': access_token
    }), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Validate input data
    errors = login_schema.validate(data)
    if errors:
        return jsonify({'error': errors}), 400
    
    # Find user by email
    user = User.query.filter_by(email=data['email']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Generate token
    access_token = create_access_token(identity=user.id)
    
    return jsonify({
        'message': 'Login successful',
        'user': profile_schema.dump(user),
        'token': access_token
    }), 200

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(profile_schema.dump(user)), 200