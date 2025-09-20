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

from twilio.twiml.messaging_response import MessagingResponse # Import for Twilio webhook

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) # Replace with a strong, random key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smssuite.db' # SQLite database
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
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", None) # TODO: Replace with your actual Twilio Account SID
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", None) # TODO: Replace with your actual Twilio Auth Token
TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER", None) # TODO: Replace with your actual Twilio Phone Number

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
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            to=format_phone_number_e164(to_number),
            from_=TWILIO_PHONE_NUMBER,
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
            db.session.commit()
            # Emit SocketIO event after message is committed to DB
            # Emit to the specific conversation room
            socketio.emit('new_message', {
                'conversation_id': conversation_id,
                'sender': 'user',
                'body': message_body,
                'timestamp': datetime.utcnow().isoformat()
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
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL, verify=False).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=SCOPES,
        prompt="select_account"
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
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL, verify=False).json()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
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
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # You want to make sure the user is verified.
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    # Create a user in your db with the information provided
    # by Google
    user = User.query.filter_by(google_id=unique_id).first()
    if not user:
        user = User(
            google_id=unique_id,
            name=users_name,
            email=users_email
        )
        db.session.add(user)
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
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0, access_type='offline', prompt='consent')
        # Save the credentials for the next run
        print("Attempting to save token.json for Sheets service...")
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
        print("token.json saved successfully for Sheets service.")
    try:
        service = build('sheets', 'v4', credentials=creds)
        return service
    except Exception as e:
        print(f"Error building Google Sheets service: {e}")
        return None

def get_google_drive_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0, access_type='offline', prompt='consent')
        print("Attempting to save token.json for Drive service...")
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
        print("token.json saved successfully for Drive service.")
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
        results = drive_service.files().list(
            q="mimeType='application/vnd.google-apps.spreadsheet'",
            fields="files(id, name)"
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
    conversations = Conversation.query.filter_by(user_id=user_id).order_by(Conversation.start_time.desc()).all()
    
    conversation_list = []
    for conv in conversations:
        last_message = Message.query.filter_by(conversation_id=conv.id).order_by(Message.timestamp.desc()).first()
        
        display_name = conv.contact.name
        if not display_name or display_name == "Unknown":
            display_name = format_phone_number_e164(conv.contact.phone_number)

        unread_count = 0
        if conv.last_read_timestamp:
            unread_count = Message.query.filter(
                Message.conversation_id == conv.id,
                Message.sender == 'contact', # Only count incoming messages as unread
                Message.timestamp > conv.last_read_timestamp
            ).count()
        else:
            # If never read, count all incoming messages as unread
            unread_count = Message.query.filter(
                Message.conversation_id == conv.id,
                Message.sender == 'contact'
            ).count()

        conversation_list.append({
            'id': conv.id,
            'contact_name': display_name,
            'last_message': last_message.body if last_message else 'No messages yet.',
            'last_message_time': last_message.timestamp.isoformat() if last_message else None,
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
            'timestamp': msg.timestamp.isoformat()
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

    # Find the user whose Twilio number matches the `to_number`
    # This assumes TWILIO_PHONE_NUMBER is unique per user or handled appropriately
    # For simplicity, we'll assume a single user for now or fetch by configuration
    # In a multi-user setup, you'd map `to_number` to a `user_id`
    # For this example, let's assume the first user in the DB (or a specific config)
    target_user = User.query.filter_by(google_id=os.environ.get("ADMIN_GOOGLE_ID")).first() # Assuming an admin user for incoming messages
    if not target_user:
        print("No target user found for incoming message.")
        return '<Response/>', 200 # Respond to Twilio without error

    contact, conversation = get_or_create_contact_and_conversation(from_number, target_user.id)

    incoming_message = Message(
        conversation_id=conversation.id,
        sender='contact',
        body=message_body
    )
    db.session.add(incoming_message)
    db.session.commit()
    
    # Emit SocketIO event for real-time update
    socketio.emit('new_message', {
        'conversation_id': conversation.id,
        'sender': 'contact',
        'body': message_body,
        'timestamp': datetime.utcnow().isoformat()
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create database tables within the application context
    # Use eventlet for Gunicorn deployment, remove ssl_context
    if os.environ.get("FLASK_ENV") == "production": # Check for production environment
        socketio.run(app, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=False, logger=False, engineio_logger=False)
    else:
        # Local development with HTTPS
        socketio.run(app, debug=True, ssl_context=('cert.pem', 'key.pem'), logger=True, engineio_logger=True)
