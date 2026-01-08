
import os
import boto3
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# AWS Configuration
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
DYNAMODB_USER_TABLE = os.getenv('DYNAMODB_USER_TABLE', 'CropYield_Users')
DYNAMODB_YIELD_TABLE = os.getenv('DYNAMODB_YIELD_TABLE', 'CropYield_Data')
SNS_TOPIC_ARN = os.getenv('SNS_TOPIC_ARN')

# Initialize AWS Clients
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns_client = boto3.client('sns', region_name=AWS_REGION)
user_table = dynamodb.Table(DYNAMODB_USER_TABLE)
yield_table = dynamodb.Table(DYNAMODB_YIELD_TABLE)

# --- Helper Functions ---

# --- Helper Functions ---

def create_user(email, password, name):
    """Creates a new user in DynamoDB."""
    try:
        # Check if user exists
        response = user_table.get_item(Key={'Email': email})
        if 'Item' in response:
            return False, "User already exists."

        # Auto-assign Admin role for testing
        role = 'admin' if email == 'admin@agri.com' else 'farmer'

        user_table.put_item(
            Item={
                'Email': email,
                'Password': password, # In production, hash this!
                'Name': name,
                'Role': role,
                'CreatedAt': datetime.now().isoformat()
            }
        )
        return True, "User created successfully."
    except ClientError as e:
        print(f"Error creating user: {e}")
        return False, str(e)

def verify_user(email, password):
    """Verifies user credentials."""
    try:
        response = user_table.get_item(Key={'Email': email})
        if 'Item' in response:
            user = response['Item']
            if user['Password'] == password:
                return True, user
        return False, None
    except ClientError as e:
        print(f"Error verifying user: {e}")
        return False, None

def add_yield_data(email, crop_name, season, yield_amount, area):
    """Adds a new yield record to DynamoDB."""
    try:
        yield_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        item = {
            'UserEmail': email,
            'Timestamp': timestamp,
            'YieldID': yield_id,
            'CropName': crop_name,
            'Season': season,
            'YieldAmount': yield_amount,
            'Area': area
        }
        yield_table.put_item(Item=item)
        return True, item
    except ClientError as e:
        print(f"Error adding yield data: {e}")
        return False, str(e)

def get_user_yields(email):
    """Retrieves yield records for a specific user."""
    try:
        response = yield_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('UserEmail').eq(email)
        )
        return response.get('Items', [])
    except ClientError as e:
        print(f"Error fetching yields: {e}")
        return []

def get_all_users():
    """Retrieves all users (For Admin)."""
    try:
        response = user_table.scan()
        return response.get('Items', [])
    except ClientError as e:
        print(f"Error scanning users: {e}")
        return []

def get_all_yields():
    """Retrieves all yield data (For Admin)."""
    try:
        response = yield_table.scan()
        return response.get('Items', [])
    except ClientError as e:
        print(f"Error scanning yields: {e}")
        return []

def send_sns_notification(message, subject="Crop Yield Alert"):
    """Sends a notification via Amazon SNS."""
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN not set. Skipping notification.")
        return

    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
    except ClientError as e:
        print(f"Error sending SNS notification: {e}")

# --- Routes ---

@app.route('/')
def index():
    # Landing page for everyone
    return render_template('index.html')

@app.route('/auth')
def auth():
    # Login/Signup Page
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('auth.html')

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    success, message = create_user(email, password, name)
    if success:
        # Determine role again to store in session (or fetch from DB, but we know logic)
        role = 'admin' if email == 'admin@agri.com' else 'farmer'
        session['user'] = {'Email': email, 'Name': name, 'Role': role}
        flash('Account created successfully!', 'success')
        send_sns_notification(f"New user signed up: {email}")
        
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    else:
        flash(message, 'error')
        return redirect(url_for('auth'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    success, user = verify_user(email, password)
    if success:
        role = user.get('Role', 'farmer') # Default to farmer if Role missing
        session['user'] = {'Email': user['Email'], 'Name': user['Name'], 'Role': role}
        flash('Logged in successfully!', 'success')
        
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid credentials.', 'error')
        return redirect(url_for('auth'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('auth'))
    
    # If admin tries to access user dashboard, redirect to admin dashboard
    if session['user'].get('Role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    user_email = session['user']['Email']
    yields = get_user_yields(user_email)
    return render_template('dashboard.html', yields=yields, user=session['user'])

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user' not in session or session['user'].get('Role') != 'admin':
        flash('Access Denied. Admins only.', 'error')
        return redirect(url_for('dashboard'))
    
    all_users = get_all_users()
    all_yields = get_all_yields()
    return render_template('admin_dashboard.html', users=all_users, yields=all_yields, user=session['user'])

@app.route('/add_yield', methods=['GET', 'POST'])
def add_yield():
    if 'user' not in session:
        return redirect(url_for('auth'))
    
    # Optional: Prevent admins from adding yield data? For now, allow it or redirect.
    # if session['user'].get('Role') == 'admin':
    #     return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        user_email = session['user']['Email']
        crop_name = request.form['crop_name']
        season = request.form['season']
        yield_amount = request.form['yield_amount']
        area = request.form['area']

        success, _ = add_yield_data(user_email, crop_name, season, yield_amount, area)
        if success:
            flash('Yield data added successfully!', 'success')
            send_sns_notification(f"User {user_email} added yield data for {crop_name}.")
            return redirect(url_for('dashboard'))
        else:
            flash('Error adding data.', 'error')

    return render_template('add_yield.html')

if __name__ == '__main__':
    # Initialize tables for development if they don't exist (Optional, assumes permission)
    # create_tables_if_not_exists() 
    app.run(debug=True, host='0.0.0.0', port=5000)
