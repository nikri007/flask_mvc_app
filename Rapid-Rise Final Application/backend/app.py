from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os, secrets, string, re
from datetime import datetime, timedelta

app = Flask(__name__)

# Configuration with YOUR Gmail credentials
app.config['SECRET_KEY'] = 'fileapp-secret-key-2025'
app.config['JWT_SECRET_KEY'] = 'fileapp-jwt-secret-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fileapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# ✅ YOUR GMAIL CONFIGURATION
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'nithinkrishna7306904340@gmail.com'  # Your Gmail
app.config['MAIL_PASSWORD'] = 'iycu nbzy kjlh bdbp'                # Your App Password

db = SQLAlchemy(app)
jwt = JWTManager(app)
mail = Mail(app)
CORS(app)
os.makedirs('uploads', exist_ok=True)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    storage_used = db.Column(db.BigInteger, default=0)
    reset_token = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_email = db.Column(db.String(120), nullable=False)
    share_token = db.Column(db.String(64), unique=True, nullable=False)
    message = db.Column(db.Text)
    expires_at = db.Column(db.DateTime, nullable=False)
    access_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Helper Functions
def validate_email(email):
    return re.match(r'^[^@]+@[^@]+\.[^@]+$', email) is not None

def validate_password(password):
    return (len(password) >= 8 and 
            re.search(r'[A-Z]', password) and 
            re.search(r'[a-z]', password) and 
            re.search(r'\d', password) and 
            re.search(r'[!@#$%^&*]', password))

def generate_token():
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))

def send_simple_email(to, subject, body):
    try:
        msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[to], body=body)
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

# Basic Routes
@app.route('/')
def home():
    return jsonify({'message': 'Fileapp Backend is running!', 'status': 'success'}), 200

@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy', 'message': 'Fileapp Backend is working'}), 200

# ✅ EMAIL TEST ROUTE
@app.route('/api/test-email/<email>')
def test_email(email):
    try:
        subject = "🎉 Fileapp Email Test"
        body = """
Hello from Fileapp!

✅ Your email configuration is working perfectly!

Your file sharing application can now:
📧 Send password reset emails globally
📁 Send file sharing notifications worldwide
🌍 Work with users anywhere in the world

Fileapp is ready for your presentation!

Best regards,
Fileapp Team
        """
        
        msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[email], body=body)
        mail.send(msg)
        return jsonify({
            'success': True, 
            'message': f'✅ Test email sent successfully to {email}!',
            'note': 'Check your inbox and spam folder'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'❌ Email failed: {str(e)}',
            'help': 'Check your Gmail app password and settings'
        }), 500

# AUTH ROUTES
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Basic validation
    required = ['first_name', 'last_name', 'email', 'password', 'confirm_password', 'date_of_birth']
    if not all(field in data for field in required):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if data['password'] != data['confirm_password']:
        return jsonify({'error': 'Passwords do not match'}), 400
    
    if not validate_email(data['email']):
        return jsonify({'error': 'Invalid email'}), 400
    
    if not validate_password(data['password']):
        return jsonify({'error': 'Password must be 8+ chars with uppercase, lowercase, number, special char'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    try:
        dob = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
        user = User(
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            password_hash=generate_password_hash(data['password']),
            date_of_birth=dob
        )
        db.session.add(user)
        db.session.commit()
        
        token = create_access_token(identity=user.id)
        return jsonify({'message': 'User created successfully', 'token': token}), 201
    except Exception as e:
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password_hash, data['password']):
        token = create_access_token(identity=user.id)
        return jsonify({'message': 'Login successful', 'token': token}), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/change-password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.get_json()
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not all(field in data for field in ['old_password', 'new_password', 'confirm_password']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if not check_password_hash(user.password_hash, data['old_password']):
        return jsonify({'error': 'Current password incorrect'}), 401
    
    if data['new_password'] != data['confirm_password']:
        return jsonify({'error': 'New passwords do not match'}), 400
    
    if not validate_password(data['new_password']):
        return jsonify({'error': 'Password requirements not met'}), 400
    
    user.password_hash = generate_password_hash(data['new_password'])
    db.session.commit()
    return jsonify({'message': 'Password changed successfully'}), 200

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    
    if not data or not data.get('email'):
        return jsonify({'error': 'Email required'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    if user:
        token = generate_token()
        user.reset_token = token
        db.session.commit()
        
        # ✅ Password reset email with your app name
        reset_link = f"http://localhost:3000?reset={token}"
        subject = "🔐 Fileapp Password Reset"
        body = f"""
Hello {user.first_name},

You requested to reset your password for your Fileapp account.

Click the link below to reset your password:
{reset_link}

This link will expire in 24 hours for security.

If you didn't request this password reset, please ignore this email.

Best regards,
Fileapp Team
        """
        
        send_simple_email(user.email, subject, body)
    
    return jsonify({'message': 'If email exists, reset link sent'}), 200

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    
    if not all(field in data for field in ['token', 'new_password', 'confirm_password']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    user = User.query.filter_by(reset_token=data['token']).first()
    if not user:
        return jsonify({'error': 'Invalid token'}), 400
    
    if data['new_password'] != data['confirm_password']:
        return jsonify({'error': 'Passwords do not match'}), 400
    
    if not validate_password(data['new_password']):
        return jsonify({'error': 'Password requirements not met'}), 400
    
    user.password_hash = generate_password_hash(data['new_password'])
    user.reset_token = None
    db.session.commit()
    return jsonify({'message': 'Password reset successful'}), 200

# FILE ROUTES
@app.route('/api/files/upload', methods=['POST'])
@jwt_required()
def upload_files():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    
    files = request.files.getlist('files')
    uploaded = []
    
    for file in files:
        if file.filename == '':
            continue
        
        # Check file size (100MB limit)
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        
        if size > 100 * 1024 * 1024:
            continue
        
        # Check user storage (1GB limit)
        if user.storage_used + size > 1024 * 1024 * 1024:
            continue
        
        filename = secure_filename(file.filename)
        stored_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{generate_token()[:8]}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
        
        file.save(filepath)
        
        file_record = File(
            original_filename=filename,
            stored_filename=stored_name,
            file_size=size,
            user_id=user_id
        )
        db.session.add(file_record)
        user.storage_used += size
        uploaded.append(filename)
    
    db.session.commit()
    return jsonify({'message': f'Uploaded {len(uploaded)} files', 'files': uploaded}), 201

@app.route('/api/files', methods=['GET'])
@jwt_required()
def list_files():
    user_id = get_jwt_identity()
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str).strip()
    per_page = 10
    
    # Build query with optional search
    query = File.query.filter_by(user_id=user_id)
    if search:
        query = query.filter(File.original_filename.ilike(f'%{search}%'))
    
    files = query.order_by(File.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    file_list = [{
        'id': f.id,
        'filename': f.original_filename,
        'size': f.file_size,
        'created_at': f.created_at.isoformat()
    } for f in files.items]
    
    return jsonify({
        'files': file_list,
        'total': files.total,
        'pages': files.pages,
        'current_page': page,
        'search': search,
        'found': len(file_list)
    }), 200

@app.route('/api/files/<int:file_id>/download', methods=['GET'])
@jwt_required()
def download_file(file_id):
    user_id = get_jwt_identity()
    file_record = File.query.filter_by(id=file_id, user_id=user_id).first()
    
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found on disk'}), 404
    
    return send_file(filepath, as_attachment=True, download_name=file_record.original_filename)

@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@jwt_required()
def delete_file(file_id):
    user_id = get_jwt_identity()
    file_record = File.query.filter_by(id=file_id, user_id=user_id).first()
    
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    # Delete file from disk
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    
    # Update user storage
    user = User.query.get(user_id)
    user.storage_used -= file_record.file_size
    
    db.session.delete(file_record)
    db.session.commit()
    return jsonify({'message': 'File deleted'}), 200

# SHARE ROUTES
@app.route('/api/share/create', methods=['POST'])
@jwt_required()
def create_share():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not all(field in data for field in ['file_id', 'recipient_email', 'expiration_hours']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    file_record = File.query.filter_by(id=data['file_id'], user_id=user_id).first()
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    if not validate_email(data['recipient_email']):
        return jsonify({'error': 'Invalid email'}), 400
    
    token = generate_token()
    expires_at = datetime.utcnow() + timedelta(hours=int(data['expiration_hours']))
    
    share = Share(
        file_id=data['file_id'],
        user_id=user_id,
        recipient_email=data['recipient_email'],
        share_token=token,
        message=data.get('message', ''),
        expires_at=expires_at
    )
    db.session.add(share)
    db.session.commit()
    
    # ✅ Send file sharing email
    user = User.query.get(user_id)
    share_url = f"http://localhost:3000?token={token}"
    subject = f"📁 {user.first_name} shared a file with you - Fileapp"
    
    email_body = f"""
Hello!

{user.first_name} {user.last_name} has shared a file with you through Fileapp.

📄 File: {file_record.original_filename}
📏 Size: {file_record.file_size / 1024 / 1024:.2f} MB
⏰ Expires: {expires_at.strftime('%B %d, %Y at %I:%M %p')}

Access the file here: {share_url}
    """
    
    if data.get('message'):
        email_body = f"""
Hello!

{user.first_name} {user.last_name} has shared a file with you through Fileapp.

💬 Personal Message:
"{data['message']}"

📄 File: {file_record.original_filename}
📏 Size: {file_record.file_size / 1024 / 1024:.2f} MB
⏰ Expires: {expires_at.strftime('%B %d, %Y at %I:%M %p')}

Access the file here: {share_url}

Best regards,
Fileapp Team
        """
    
    send_simple_email(data['recipient_email'], subject, email_body)
    
    return jsonify({'message': 'File shared successfully', 'share_url': share_url}), 201

@app.route('/api/share/my-shares', methods=['GET'])
@jwt_required()
def my_shares():
    user_id = get_jwt_identity()
    shares = Share.query.filter_by(user_id=user_id).order_by(Share.created_at.desc()).all()
    
    share_list = []
    for s in shares:
        file_record = File.query.get(s.file_id)
        file_name = file_record.original_filename if file_record else "Unknown File"
        
        share_list.append({
            'id': s.id,
            'file_id': s.file_id,
            'file_name': file_name,
            'recipient_email': s.recipient_email,
            'created_at': s.created_at.isoformat(),
            'expires_at': s.expires_at.isoformat(),
            'access_count': s.access_count,
            'expired': s.expires_at < datetime.utcnow(),
            'accessed': s.access_count > 0
        })
    
    return jsonify({'shares': share_list}), 200

@app.route('/api/share/public/<token>', methods=['GET'])
def public_file_info(token):
    share = Share.query.filter_by(share_token=token).first()
    
    if not share or share.expires_at < datetime.utcnow():
        return jsonify({'error': 'Share not found or expired'}), 404
    
    file_record = File.query.get(share.file_id)
    user = User.query.get(share.user_id)
    
    return jsonify({
        'filename': file_record.original_filename,
        'size': file_record.file_size,
        'message': share.message,
        'sender': f"{user.first_name} {user.last_name}",
        'expires_at': share.expires_at.isoformat()
    }), 200

@app.route('/api/share/public/<token>/download', methods=['GET'])
def download_shared_file(token):
    share = Share.query.filter_by(share_token=token).first()
    
    if not share or share.expires_at < datetime.utcnow():
        return jsonify({'error': 'Share not found or expired'}), 404
    
    file_record = File.query.get(share.file_id)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    # Track access
    share.access_count += 1
    db.session.commit()
    
    return send_file(filepath, as_attachment=True, download_name=file_record.original_filename)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("🎉 Fileapp Database Created!")
        print("✅ Gmail Configuration: READY")
        print(f"📧 Email: {app.config['MAIL_USERNAME']}")
        print("🌍 Global Email Delivery: ENABLED")
        print("🔧 Test Email: http://localhost:5000/api/test-email/youremail@gmail.com")
        print("🚀 Fileapp Server: http://localhost:5000")
        print("📱 Frontend: http://localhost:3000")
        print("=" * 60)
        print("🎯 YOUR FILEAPP IS READY FOR PRESENTATION!")
    app.run(debug=True, port=5000)