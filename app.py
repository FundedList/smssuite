import eventlet # Add eventlet import
eventlet.monkey_patch() # Must be at the very top!

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import json
from datetime import datetime
from dotenv import load_dotenv
import phonenumbers
from flask_socketio import SocketIO, emit, join_room, leave_room # Added leave_room
from flask_login import current_user

load_dotenv() # Load environment variables from .env file

# Google Sheets API imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Flask-Login imports
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

# SQLAlchemy imports for database
from flask_sqlalchemy import SQLAlchemy

# Twilio imports
from twilio.rest import Client

# Google OAuth imports
from oauthlib.oauth2 import WebApplicationClient
import requests
import httpx # Added httpx import

from twilio.twiml.messaging_response import MessagingResponse # Import for Twilio webhook
import tempfile # Added tempfile import

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) # Replace with a strong, random key in production
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", 'sqlite:///smssuite.db') # Use DATABASE_URL for PostgreSQL on Render
print(f"SQLALCHEMY_DATABASE_URI: {app.config['SQLALCHEMY_DATABASE_URI']}") # Diagnostic print
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page' # Changed to point to the new login route
socketio = SocketIO(app, cors_allowed_origins="*", logger=False, engineio_logger=False) # Initialize SocketIO with logging

# User model for Flask-Login
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    google_api_refresh_token = db.Column(db.Text, nullable=True) # For user-specific Google API access
    google_api_access_token = db.Column(db.Text, nullable=True) # For user-specific Google API access (short-lived)
    twilio_account_sid = db.Column(db.String(100), nullable=True)
    twilio_auth_token = db.Column(db.String(100), nullable=True)
    twilio_phone_number = db.Column(db.String(20), nullable=True, unique=True)

# Contact model
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100))

    __table_args__ = (db.UniqueConstraint('user_id', 'phone_number', name='uq_user_phone'),)

# Conversation model
class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id'), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    last_read_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=True) # New field
    last_activity_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False) # New field

    # Relationships
    contact = db.relationship('Contact', backref=db.backref('conversations', lazy=True), lazy=True)
    messages = db.relationship('Message', backref='conversation', lazy=True, order_by='Message.timestamp')

# Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    sender = db.Column(db.String(50), nullable=False) # e.g., 'user' or 'contact'
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Configuration for Google Sheets API
SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly', 'https://www.googleapis.com/auth/drive.readonly', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email', 'openid']
GOOGLE_SHEET_ID = os.environ.get("GOOGLE_SHEET_ID", 'YOUR_GOOGLE_SHEET_ID') # TODO: Replace with your actual Google Sheet ID
GOOGLE_SHEET_RANGE = os.environ.get("GOOGLE_SHEET_RANGE", 'Sheet1!A:C') # TODO: Adjust range as needed (e.g., Name, Phone, Group)

# Twilio Configuration
# TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", None) # TODO: Replace with your actual Twilio Account SID
# TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", None) # TODO: Replace with your actual Twilio Auth Token
# TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER", None) # TODO: Replace with your actual Twilio Phone Number

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Before the first request, create database tables
# @app.before_first_request # DEPRECATED IN FLASK 2.3+
# def create_tables():
#     db.create_all()

# Helper to format phone numbers
def format_phone_number_e164(phone_number, default_region="US"):
    try:
        parsed_number = phonenumbers.parse(phone_number, default_region)
        if phonenumbers.is_valid_number(parsed_number):
            return phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
        # If not valid but potentially missing country code, try with US default
        if not phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164).startswith('+'):
             parsed_number = phonenumbers.parse(phone_number, default_region)
             if phonenumbers.is_valid_number(parsed_number):
                 return phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)

    except phonenumbers.NumberParseException:
        pass # Fallback to original if parsing fails
    return phone_number # Return original if cannot format

def get_or_create_contact_and_conversation(phone_number, user_id, contact_name="Unknown"):
    formatted_phone_number = format_phone_number_e164(phone_number)
    contact = Contact.query.filter_by(user_id=user_id, phone_number=formatted_phone_number).first()
    if not contact:
        contact = Contact(user_id=user_id, phone_number=formatted_phone_number, name=contact_name)
        db.session.add(contact)
        db.session.commit()

    conversation = Conversation.query.filter_by(user_id=user_id, contact_id=contact.id).first()
    if not conversation:
        conversation = Conversation(user_id=user_id, contact_id=contact.id)
        db.session.add(conversation)
        db.session.commit()
    return contact, conversation

def send_sms(to_number, message_body, conversation_id=None):
    # Use current_user's Twilio credentials
    if not current_user.is_authenticated or \
       not current_user.twilio_account_sid or \
       not current_user.twilio_auth_token or \
       not current_user.twilio_phone_number:
        error_message = "Twilio credentials not configured for your account. Please go to Settings to configure."
        print(f"Error sending SMS: {error_message}")
        return False, error_message

    try:
        client = Client(current_user.twilio_account_sid, current_user.twilio_auth_token)
        message = client.messages.create(
            to=format_phone_number_e164(to_number),
            from_=current_user.twilio_phone_number,
            body=message_body
        )
        print(f"Message SID: {message.sid}")

        if conversation_id:
            new_message = Message(
                conversation_id=conversation_id,
                sender='user',
                body=message_body
            )
            db.session.add(new_message)
            conversation = Conversation.query.get(conversation_id)
            conversation.last_activity_time = datetime.utcnow() # Update last activity time
            db.session.commit()
            # Emit SocketIO event after message is committed to DB
            # Emit to the specific conversation room
            socketio.emit('new_message', {
                'conversation_id': conversation_id,
                'sender': 'user',
                'body': message_body,
                'timestamp': datetime.utcnow().isoformat() + 'Z' # Ensure Z for UTC
            }, room=str(conversation_id))
            # Emit to the user's personal room to update conversation list
            socketio.emit('conversation_update', {'user_id': current_user.id}, room=str(current_user.id))

        return True, f"Message sent to {to_number}."
    except Exception as e:
        print(f"Error sending SMS to {to_number}: {e}")
        return False, f"Error sending SMS to {to_number}: {e}"

@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # Original Google OAuth redirect logic
    google_provider_cfg = httpx.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=SCOPES,
        prompt="consent", # Ensure we get a refresh token
        access_type="offline" # Request offline access for refresh token
    )
    return redirect(request_uri)

@app.route('/login_page') # New route for rendering the login.html
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/login/callback')
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = httpx.get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = httpx.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that you have tokens (yay!) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # but make sure to use a tool that will get the `openid-configuration`
    # once and cache it.
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(
        userinfo_endpoint
    )
    userinfo_response = httpx.get(uri, headers=headers)

    # You want to make sure the user is verified.
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
        # Extract tokens for future API access
        refresh_token = client.refresh_token # The refresh token
        access_token = client.token['access_token'] # The current access token
    else:
        return "User email not available or not verified by Google.", 400

    # Create a user in your db with the information provided
    # by Google
    user = User.query.filter_by(google_id=unique_id).first()
    if not user:
        user = User(
            google_id=unique_id,
            name=users_name,
            email=users_email,
            google_api_refresh_token=refresh_token,
            google_api_access_token=access_token
        )
        db.session.add(user)
    else:
        # Update existing user's tokens
        user.name = users_name
        user.email = users_email
        user.google_api_refresh_token = refresh_token
        user.google_api_access_token = access_token
    db.session.commit()

    # Log user in
    login_user(user)

    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

# Helper to get the Google Sheets service
def get_google_sheet_service():
    # For multi-user access, use current_user's stored tokens
    if not current_user.is_authenticated or not current_user.google_api_refresh_token:
        print("Error: Current user not authenticated or no Google API refresh token found.")
        return None

    creds = Credentials(
        token=current_user.google_api_access_token,
        refresh_token=current_user.google_api_refresh_token,
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        token_uri="https://oauth2.googleapis.com/token",
        scopes=SCOPES
    )

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            # Update the stored access token in the database
            current_user.google_api_access_token = creds.token
            db.session.commit()
        except Exception as e:
            print(f"Error refreshing Google API access token for Sheets: {e}")
            return None

    if not creds.valid:
        print("Error: Google API credentials are not valid after refresh attempt for Sheets.")
        return None

    try:
        service = build('sheets', 'v4', credentials=creds)
        return service
    except Exception as e:
        print(f"Error building Google Sheets service: {e}")
        return None



def get_google_drive_service():
    # For multi-user access, use current_user's stored tokens
    if not current_user.is_authenticated or not current_user.google_api_refresh_token:
        print("Error: Current user not authenticated or no Google API refresh token found.")
        return None

    creds = Credentials(
        token=current_user.google_api_access_token,
        refresh_token=current_user.google_api_refresh_token,
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        token_uri="https://oauth2.googleapis.com/token",
        scopes=SCOPES
    )

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            # Update the stored access token in the database
            current_user.google_api_access_token = creds.token
            db.session.commit()
        except Exception as e:
            print(f"Error refreshing Google API access token for Drive: {e}")
            return None

    if not creds.valid:
        print("Error: Google API credentials are not valid after refresh attempt for Drive.")
        return None
    try:
        service = build('drive', 'v3', credentials=creds)
        return service
    except Exception as e:
        print(f"Error building Google Drive service: {e}")
        return None


@app.route('/google_sheets')
@login_required
def list_google_sheets():
    drive_service = get_google_drive_service()
    if not drive_service:
        return jsonify({'error': 'Could not get Google Drive service.'}), 500
    
    try:
        search_query = request.args.get('search', '')
        q_param = "mimeType='application/vnd.google-apps.spreadsheet'"
        if search_query:
            q_param += f" and name contains '{search_query}'"
            
        results = drive_service.files().list(
            q=q_param,
            fields="files(id, name)",
            supportsAllDrives=True, # Added to support Shared Drives
            includeItemsFromAllDrives=True # Added to include items from Shared Drives
        ).execute()
        sheets = results.get('files', [])
        return jsonify(sheets)
    except Exception as e:
        print(f"Error listing Google Sheets: {e}")
        return jsonify({'error': f'Error listing sheets: {e}'}), 500

@app.route('/google_sheet_data/<sheet_id>')
@login_required
def get_google_sheet_data(sheet_id):
    sheet_service = get_google_sheet_service()
    if not sheet_service:
        return jsonify({'error': 'Could not get Google Sheets service.'}), 500

    try:
        # Try to get the first sheet's data
        spreadsheet_metadata = sheet_service.spreadsheets().get(spreadsheetId=sheet_id).execute()
        sheet_name = spreadsheet_metadata.get('sheets')[0].get('properties').get('title')
        range_name = f'{sheet_name}!A:Z' # Get all columns up to Z
        result = sheet_service.spreadsheets().values().get(
            spreadsheetId=sheet_id, range=range_name).execute()
        values = result.get('values', [])
        
        if not values:
            return jsonify({'headers': [], 'data': []})

        headers = values[0]
        data = values[1:]
        return jsonify({'headers': headers, 'data': data})
    except Exception as e:
        print(f"Error reading Google Sheet data for {sheet_id}: {e}")
        return jsonify({'error': f'Error reading sheet data: {e}', 'headers': [], 'data': []}), 500


def get_contacts_from_sheet():
    service = get_google_sheet_service()
    if not service:
        return []
    try:
        result = service.spreadsheets().values().get(
            spreadsheetId=GOOGLE_SHEET_ID, range=GOOGLE_SHEET_RANGE).execute()
        values = result.get('values', [])
        # Assuming the first row is headers, skip it and parse contacts
        contacts = []
        if values and len(values) > 1: # Ensure there's at least one data row after headers
            for row in values[1:]: # Skip header row
                if len(row) >= 2: # Ensure at least phone number and name
                    contacts.append({'name': row[0], 'phone': row[1]})
        return contacts
    except Exception as e:
        print(f"Error reading from Google Sheet: {e}")
        return []

@app.route('/send_templated_bulk_sms', methods=['POST'])
@login_required
def send_templated_bulk_sms():
    data = request.get_json()
    sheet_id = data.get('sheet_id')
    message_template = data.get('message_template')

    if not sheet_id or not message_template:
        return jsonify({'error': 'Missing sheet ID or message template.'}), 400

    # Fetch sheet data
    sheet_data_response = get_google_sheet_data(sheet_id)
    sheet_data = json.loads(sheet_data_response.data) # Deserialize jsonify response

    if sheet_data.get('error'):
        return jsonify({'error': f'Error fetching sheet data: {sheet_data['error']}'}), 500

    headers = sheet_data.get('headers', [])
    rows = sheet_data.get('data', [])

    if not headers or not rows:
        return jsonify({'message': 'No data found in the selected sheet.'}), 200

    results = []
    for row in rows:
        # Create a dictionary for easy templating
        row_data = {headers[i]: row[i] for i in range(len(headers)) if i < len(row)}
        
        # Personalize message
        personalized_message = message_template
        for key, value in row_data.items():
            personalized_message = personalized_message.replace(f'{{{{{key}}}}}', str(value))

        # Assuming phone number is in a column named 'Phone' or similar
        # This needs to be robust, for now, let's try to find common names or default to a column index
        phone_number = None
        if 'Phone' in headers:
            phone_index = headers.index('Phone')
            if phone_index < len(row):
                phone_number = row[phone_index]
        elif 'phone' in headers:
            phone_index = headers.index('phone')
            if phone_index < len(row):
                phone_number = row[phone_index]
        elif len(row) > 1: # Fallback to second column if no 'Phone' header found
            phone_number = row[1] # Assuming 2nd column is phone number (index 1)
        
        if phone_number:
            # Get or create contact and conversation for the current user and phone number
            contact, conversation = get_or_create_contact_and_conversation(phone_number, current_user.id, _get_contact_name_from_row_data(row_data, headers))

            success, feedback_message = send_sms(phone_number, personalized_message, conversation.id)
            results.append(f"To {row_data.get('Name', phone_number)}: {feedback_message}") # Use Name if available
        else:
            results.append(f"Skipped row (no phone number found): {row}")

    return jsonify({'message': 'Bulk SMS process completed.', 'results': results}), 200


def _get_contact_name_from_row_data(row_data, headers):
    # Prioritize 'Name', then 'First Name' + 'Last Name', then 'FirstName', then 'LastName', then empty string
    if 'Name' in row_data and row_data['Name']:
        return row_data['Name']
    
    first_name = row_data.get('First Name', row_data.get('FirstName', ''))
    last_name = row_data.get('Last Name', row_data.get('LastName', ''))

    if first_name and last_name:
        return f"{first_name} {last_name}"
    elif first_name:
        return first_name
    elif last_name:
        return last_name
    return '' # Return empty string if no name found

@app.route('/api/conversations')
@login_required
def get_conversations():
    user_id = current_user.id
    # Order conversations by last_activity_time in descending order, with NULLs last
    # This ensures that conversations with no activity time (e.g., brand new ones) appear at the end.
    conversations = Conversation.query.filter_by(user_id=user_id).order_by(db.desc(Conversation.last_activity_time.isnot(None)), Conversation.last_activity_time.desc()).all()
    
    conversation_list = []
    for conv in conversations:
        print(f"Processing Conversation ID: {conv.id}")
        print(f"  Contact Name (raw): {conv.contact.name if conv.contact else 'No Contact Object'}")
        print(f"  Contact Phone (raw): {conv.contact.phone_number if conv.contact else 'No Contact Object'}")
        print(f"  Last Activity Time (raw): {conv.last_activity_time}")

        last_message_timestamp_str = None
        last_message_body = '' # Default to empty string for preview

        # Fetch the very last message for the conversation to get its body and ensure last_activity_time accuracy
        last_message_record = Message.query.filter_by(conversation_id=conv.id).order_by(Message.timestamp.desc()).first()
        if last_message_record:
            if conv.last_activity_time is None or last_message_record.timestamp > conv.last_activity_time:
                # This can happen if last_activity_time was null or not updated during initial import
                conv.last_activity_time = last_message_record.timestamp
                db.session.add(conv) # Mark for update
            last_message_timestamp_str = last_message_record.timestamp.isoformat() + 'Z'
            last_message_body = last_message_record.body
            print(f"  Last Message Record Timestamp: {last_message_record.timestamp}")
            print(f"  Last Message Record Body: {last_message_record.body[:30]}...") # Truncate for log readability
        # else: if no messages, last_message_timestamp_str and last_message_body remain defaults

        # Ensure contact name is displayed as phone number if not available
        display_contact_name = conv.contact.name if conv.contact and conv.contact.name else (format_phone_number_e164(conv.contact.phone_number) if conv.contact and conv.contact.phone_number else 'Unknown Contact/Phone')
        print(f"  Display Contact Name (processed): {display_contact_name}")

        unread_count = 0
        if conv.last_read_timestamp:
            unread_count = Message.query.filter(
                Message.conversation_id == conv.id,
                Message.sender == 'contact', # Only count incoming messages as unread
                Message.timestamp > conv.last_read_timestamp
            ).count()
        else:
            # If no last_read_timestamp, all incoming messages are unread
            unread_count = Message.query.filter(
                Message.conversation_id == conv.id,
                Message.sender == 'contact'
            ).count()
        print(f"  Unread Count: {unread_count}")
        print("----------------------------------------")

        conversation_list.append({
            'id': conv.id,
            'contact_name': display_contact_name,
            'phone_number': format_phone_number_e164(conv.contact.phone_number) if conv.contact and conv.contact.phone_number else None,
            'last_message_time': last_message_timestamp_str,
            'last_message_body': last_message_body, # Add last message body for preview
            'unread_count': unread_count
        })
    return jsonify(conversation_list)

@app.route('/api/conversations/<int:conversation_id>/messages')
@login_required
def get_conversation_messages(conversation_id):
    user_id = current_user.id
    conversation = Conversation.query.filter_by(id=conversation_id, user_id=user_id).first_or_404()
    messages = Message.query.filter_by(conversation_id=conversation.id).order_by(Message.timestamp.asc()).all()

    message_list = []
    for msg in messages:
        message_list.append({
            'id': msg.id,
            'sender': msg.sender,
            'body': msg.body,
            'timestamp': msg.timestamp.isoformat() + 'Z' # Ensure Z for UTC
        })
    return jsonify({'conversation_id': conversation.id, 'messages': message_list})

@app.route('/api/conversations/<int:conversation_id>/mark_read', methods=['POST'])
@login_required
def mark_conversation_as_read(conversation_id):
    user_id = current_user.id
    conversation = Conversation.query.filter_by(id=conversation_id, user_id=user_id).first_or_404()

    print(f"Attempting to mark conversation {conversation_id} as read. Current last_read_timestamp: {conversation.last_read_timestamp}")

    if conversation.last_read_timestamp is None or conversation.last_read_timestamp < datetime.utcnow():
        conversation.last_read_timestamp = datetime.utcnow()
        db.session.commit()
        print(f"Conversation {conversation_id} marked as read. New last_read_timestamp: {conversation.last_read_timestamp}")
        socketio.emit('conversation_update', {'user_id': current_user.id}, room=str(current_user.id)) # Notify for unread count update
    else:
        print(f"Conversation {conversation_id} already read (or timestamp is future). No update needed.")

    return jsonify({'message': 'Conversation marked as read.'}), 200

@app.route('/api/start_conversation', methods=['POST'])
@login_required
def start_conversation():
    data = request.get_json()
    phone_numbers_str = data.get('phone_numbers')
    initial_message = data.get('initial_message', '')
    contact_name_input = data.get('contact_name', '') # New: Optional contact name
    
    if not phone_numbers_str:
        return jsonify({'error': 'Phone numbers are required.'}), 400

    phone_numbers = [num.strip() for num in phone_numbers_str.split(',') if num.strip()]
    if not phone_numbers:
        return jsonify({'error': 'Invalid phone numbers provided.'}), 400

    conversations_started = []
    for p_num in phone_numbers:
        # Use provided contact_name_input, otherwise default to phone number for display
        display_name = contact_name_input if contact_name_input else p_num
        contact, conversation = get_or_create_contact_and_conversation(p_num, current_user.id, display_name)
        if initial_message:
            success, feedback = send_sms(p_num, initial_message, conversation.id)
            conversations_started.append({'phone': p_num, 'conversation_id': conversation.id, 'status': feedback})
        else:
            conversations_started.append({'phone': p_num, 'conversation_id': conversation.id, 'status': 'Conversation started without initial message.'})
    
    return jsonify({'message': 'Conversations initiated.', 'conversations': conversations_started}), 200

@app.route('/api/send_message/<int:conversation_id>', methods=['POST'])
@login_required
def send_message_in_conversation(conversation_id):
    user_id = current_user.id
    conversation = Conversation.query.filter_by(id=conversation_id, user_id=user_id).first_or_404()
    data = request.get_json()
    message_body = data.get('message')

    if not message_body:
        return jsonify({'error': 'Message body cannot be empty.'}), 400
    
    success, feedback_message = send_sms(conversation.contact.phone_number, message_body, conversation.id)

    if success:
        return jsonify({'message': feedback_message}), 200
    else:
        return jsonify({'error': feedback_message}), 500

@app.route('/twilio_webhook', methods=['POST'])
def twilio_webhook():
    # Twilio sends data as form-encoded, not JSON
    from_number = request.form.get('From')
    to_number = request.form.get('To') # Our Twilio number
    message_body = request.form.get('Body')

    if not from_number or not message_body:
        return 'Invalid Twilio request', 400

    formatted_from_number = format_phone_number_e164(from_number)
    formatted_to_number = format_phone_number_e164(to_number)

    target_user = None
    conversation = None

    # Priority 1: Find an existing conversation for this contact number
    # This ensures replies go to the user who initiated the conversation
    conversation = Conversation.query.join(Contact).filter(
        Contact.phone_number == formatted_from_number
    ).order_by(Conversation.start_time.desc()).first()

    if conversation:
        target_user = User.query.get(conversation.user_id)
    else:
        # Priority 2: If no conversation, find a user whose Twilio number matches the `to_number`
        # This routes unsolicited messages to the user who owns the Twilio number
        print(f"No existing conversation found for {formatted_from_number}. Looking for user with Twilio number: {formatted_to_number}")
        target_user = User.query.filter_by(twilio_phone_number=formatted_to_number).first()

    if not target_user:
        # Fallback: If still no target user (e.g., Twilio number not configured or unroutable)
        print("No target user found for incoming message. Falling back to ADMIN_GOOGLE_ID if configured.")
        target_user = User.query.filter_by(google_id=os.environ.get("ADMIN_GOOGLE_ID")).first()

    if not target_user:
        print("Error: No target user identified for incoming message. Message will not be processed.")
        return '<Response/>', 200 # Respond to Twilio gracefully if no user can be found

    # Now that we have a target_user, get or create the contact and conversation for them
    # The conversation might have been found above, or it needs to be created for unsolicited messages
    contact, conversation = get_or_create_contact_and_conversation(formatted_from_number, target_user.id)

    incoming_message = Message(
        conversation_id=conversation.id,
        sender='contact',
        body=message_body
    )
    db.session.add(incoming_message)
    conversation.last_activity_time = datetime.utcnow() # Update last activity time
    db.session.commit()
    
    # Emit SocketIO event for real-time update
    socketio.emit('new_message', {
        'conversation_id': conversation.id,
        'sender': 'contact',
        'body': message_body,
        'timestamp': datetime.utcnow().isoformat() + 'Z' # Ensure Z for UTC
    }, room=str(conversation.id))
    socketio.emit('conversation_update', {'user_id': target_user.id}, room=str(target_user.id))

    resp = MessagingResponse()
    # You can optionally send a reply here, e.g., resp.message("Thanks for your message!")
    return str(resp)

@socketio.on('connect')
def handle_connect():
    print("Client connected!")
    if current_user.is_authenticated:
        user_room = str(current_user.id)
        join_room(user_room)
        print(f"User {current_user.id} joined room {user_room} on connect")

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected.")
    # You might want to remove client from rooms here, but typically handled by SocketIO itself.

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    print(f"Client joined room: {room}")

@socketio.on('leave') # New leave event
def on_leave(data):
    room = data['room']
    leave_room(room)
    print(f"Client left room: {room}")

# Deprecated routes for single/multiple/bulk SMS from previous iteration, can be removed later
@app.route('/send_single', methods=['POST'])
@login_required
def send_single():
    to_number = request.form['to']
    message_body = request.form['message']
    success, feedback_message = send_sms(to_number, message_body)
    return render_template('index.html', message=feedback_message)

@app.route('/send_multiple', methods=['POST'])
@login_required
def send_multiple():
    to_numbers_str = request.form['to']
    message_body = request.form['message']
    to_numbers = [num.strip() for num in to_numbers_str.split(',') if num.strip()]

    results = []
    for number in to_numbers:
        success, feedback_message = send_sms(number, message_body)
        results.append(feedback_message)
    
    return render_template('index.html', message='\n'.join(results))

@app.route('/send_bulk', methods=['POST'])
@login_required
def send_bulk():
    message_body = request.form['message']
    contacts = get_contacts_from_sheet()

    if not contacts:
        return render_template('index.html', message="No contacts found in Google Sheet or error retrieving them.")

    results = []
    for contact in contacts:
        success, feedback_message = send_sms(contact['phone'], message_body)
        results.append(f"To {contact['name']} ({contact['phone']}): {feedback_message}") # Use Name if available
    
    return render_template('index.html', message='\n'.join(results))

@app.route('/settings')
@login_required
def settings_page():
    return render_template('settings.html',
                           email=current_user.email,
                           twilio_account_sid=current_user.twilio_account_sid,
                           twilio_auth_token=current_user.twilio_auth_token,
                           twilio_phone_number=current_user.twilio_phone_number)

@app.route('/api/configure_twilio', methods=['POST'])
@login_required
def configure_twilio():
    data = request.get_json()
    account_sid = data.get('account_sid')
    auth_token = data.get('auth_token')
    phone_number = data.get('phone_number')

    print(f"Received Twilio config: SID={account_sid[:5]}***, Token={auth_token[:5]}***, Phone={phone_number}") # Log redacted credentials

    if not account_sid or not auth_token or not phone_number:
        return jsonify({'error': 'All Twilio fields are required.'}), 400

    # Validate phone number format (optional, but good practice)
    formatted_phone_number = format_phone_number_e164(phone_number)
    if not formatted_phone_number:
        return jsonify({'error': 'Invalid Twilio phone number format.'}), 400

    # Check if the Twilio phone number is already registered by another user
    existing_user_with_phone = User.query.filter_by(twilio_phone_number=formatted_phone_number).first()
    if existing_user_with_phone and existing_user_with_phone.id != current_user.id:
        return jsonify({'error': 'This Twilio phone number is already associated with another account.'}), 409 # Conflict

    try:
        current_user.twilio_account_sid = account_sid
        current_user.twilio_auth_token = auth_token
        current_user.twilio_phone_number = formatted_phone_number
        db.session.commit()
        print(f"Successfully committed Twilio credentials for user {current_user.id}.")
        return jsonify({'message': 'Twilio credentials saved successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error saving Twilio credentials: {e}")
        return jsonify({'error': f'Error saving Twilio credentials: {e}'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create database tables within the application context
    # Use eventlet for Gunicorn deployment, remove ssl_context
    if os.environ.get("FLASK_ENV") == "production": # Check for production environment
        socketio.run(app, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=False, logger=False, engineio_logger=False)
    else:
        # Local development with HTTPS
        socketio.run(app, debug=True, ssl_context=('cert.pem', 'key.pem'), logger=True, engineio_logger=True)

@app.route('/api/import_twilio_history', methods=['POST'])
@login_required
def trigger_twilio_history_import():
    if not current_user.twilio_account_sid or \
       not current_user.twilio_auth_token or \
       not current_user.twilio_phone_number:
        return jsonify({'error': 'Twilio credentials not configured for your account.'}), 400
    
    # In a real application, this would be a long-running task, possibly in a background job.
    # For simplicity, we'll run it synchronously for now.
    # success, message = import_twilio_history_for_user(current_user)
    
    # Run the import in a separate greenlet to avoid blocking the main event loop
    eventlet.spawn(import_twilio_history_for_user, current_user._get_current_object())
    
    # Return immediately, the import will proceed in the background
    return jsonify({'message': 'Twilio history import initiated in the background. Check server logs for progress.'}), 202 # 202 Accepted for background processing

def import_twilio_history_for_user(user):
    print(f"Starting Twilio history import for user {user.id} ({user.email})...")
    # TODO: Implement actual Twilio API calls and database insertion here
    try:
        client = Client(user.twilio_account_sid, user.twilio_auth_token)
        # Fetch messages
        # messages = client.messages.list(to=user.twilio_phone_number, limit=100) # Example: fetch messages sent to user's Twilio number
        # messages = client.messages.list(from_=user.twilio_phone_number, limit=100) # Example: fetch messages sent from user's Twilio number
        
        # To get all messages (sent and received) related to the user's Twilio number,
        # we'll fetch messages where the user's Twilio number is either 'from' or 'to'.
        # This might require two separate queries and merging/deduplicating, or iterating more broadly.
        
        # A more robust approach would be to iterate through all messages in the account
        # and filter them by the user's Twilio number.
        
        # Let's simplify for now: fetch all messages for the account and filter by the user's Twilio number
        all_messages = client.messages.list()
        
        print(f"Fetched {len(all_messages)} total messages from Twilio account.")
        
        imported_count = 0
        for message_record in all_messages:
            # Normalize Twilio message numbers to E.164 for reliable comparison
            twilio_from_e164 = format_phone_number_e164(message_record.from_)
            twilio_to_e164 = format_phone_number_e164(message_record.to)
            
            print(f"  Processing Twilio message SID: {message_record.sid}, From: {twilio_from_e164}, To: {twilio_to_e164}")
            print(f"  User's Twilio number (E.164): {user.twilio_phone_number}")

            is_from_user_twilio = (twilio_from_e164 == user.twilio_phone_number)
            is_to_user_twilio = (twilio_to_e164 == user.twilio_phone_number)
            
            if not (is_from_user_twilio or is_to_user_twilio):
                print(f"  Skipping message {message_record.sid}: not relevant to user's Twilio number.")
                continue # Skip messages not involving this user's Twilio number

            # Determine sender and recipient in the context of our app
            if is_from_user_twilio: # User sent the message
                app_sender = 'user'
                contact_phone = message_record.to
            else: # User received the message
                app_sender = 'contact'
                contact_phone = message_record.from_
            
            # Skip if contact_phone is the user's own Twilio number (e.g., messages to self)
            if format_phone_number_e164(contact_phone) == user.twilio_phone_number:
                continue

            # Convert Twilio timestamp to datetime object
            # Twilio timestamp is typically in RFC 2822 format or similar, can be parsed by datetime.fromisoformat
            # Example: 'Thu, 24 Sep 2025 10:00:00 +0000'
            # Twilio's date_sent is a datetime object directly
            # Convert it to timezone-naive UTC for consistency with database entries
            message_timestamp = message_record.date_sent.replace(tzinfo=None)

            # Get or create contact and conversation
            contact, conversation = get_or_create_contact_and_conversation(contact_phone, user.id)

            # Check for existing message to avoid duplicates
            existing_message = Message.query.filter_by(
                conversation_id=conversation.id,
                sender=app_sender,
                body=message_record.body,
                timestamp=message_timestamp # Exact timestamp match
            ).first()
            
            if existing_message:
                # print(f"Skipping duplicate message: {message_record.sid}")
                continue # Skip if message already exists

            new_message = Message(
                conversation_id=conversation.id,
                sender=app_sender,
                body=message_record.body,
                timestamp=message_timestamp
            )
            db.session.add(new_message)

            # Update conversation's last_activity_time if this message is more recent
            if conversation.last_activity_time is None or new_message.timestamp > conversation.last_activity_time:
                conversation.last_activity_time = new_message.timestamp
                
            imported_count += 1
            # print(f"Imported message: {message_record.sid}")
        
        db.session.commit()
        print(f"Successfully imported {imported_count} messages for user {user.id}.")
        # Emit a global update or a user-specific update to refresh UI
        socketio.emit('conversation_update', {'user_id': user.id}, room=str(user.id))
        return True, f"Successfully imported {imported_count} historical Twilio messages."
    except Exception as e:
        db.session.rollback()
        print(f"Error importing Twilio history for user {user.id}: {e}")
        return False, f"Error importing Twilio history: {e}"
