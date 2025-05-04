from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.contact import Contact
from app.schemas.contact import ContactSchema
import json
from sqlalchemy import or_

contacts_bp = Blueprint('contacts', __name__)
contact_schema = ContactSchema()
contacts_schema = ContactSchema(many=True)

@contacts_bp.route('/', methods=['POST'])
@jwt_required()
def create_contact():
    data = request.get_json()
    current_user_id = get_jwt_identity()
    
    # Validate input data
    errors = contact_schema.validate(data)
    if errors:
        return jsonify({'error': errors}), 400
    
    # Handle phone numbers - ensure it's properly formatted for database storage
    phone_numbers = data.get('phone_numbers', [])
    if isinstance(phone_numbers, list):
        phone_numbers = json.dumps(phone_numbers)
    
    # Create new contact
    contact = Contact(
        user_id=current_user_id,
        first_name=data['first_name'],
        last_name=data['last_name'],
        address=data.get('address'),
        company=data.get('company'),
        phone_numbers=phone_numbers
    )
    
    db.session.add(contact)
    db.session.commit()
    
    return jsonify({
        'message': 'Contact created successfully',
        'contact': contact_schema.dump(contact)
    }), 201

@contacts_bp.route('/', methods=['GET'])
@jwt_required()
def get_contacts():
    current_user_id = get_jwt_identity()
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    
    # Build query
    query = Contact.query.filter_by(user_id=current_user_id)
    
    # Add search filter if provided
    if search:
        search_filter = or_(
            Contact.first_name.ilike(f'%{search}%'),
            Contact.last_name.ilike(f'%{search}%'),
            Contact.company.ilike(f'%{search}%')
        )
        query = query.filter(search_filter)
    
    # Execute query with pagination
    paginated_contacts = query.order_by(Contact.created_at.desc()).paginate(page=page, per_page=per_page)
    
    # Prepare response
    result = {
        'contacts': contacts_schema.dump(paginated_contacts.items),
        'page': page,
        'per_page': per_page,
        'total': paginated_contacts.total,
        'pages': paginated_contacts.pages
    }
    
    return jsonify(result), 200

# Other routes remain the same...