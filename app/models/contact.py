from app import db
from datetime import datetime

class Contact(db.Model):
    __tablename__ = 'contacts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    address = db.Column(db.Text, nullable=True)
    company = db.Column(db.String(100), nullable=True)
    phone_numbers = db.Column(db.Text, nullable=True)  # Store as JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Contact {self.first_name} {self.last_name}>'