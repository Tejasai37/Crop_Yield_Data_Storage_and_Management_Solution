
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

def create_user(email, password, name, role='farmer'):
    """Creates a new user in DynamoDB."""
    try:
        # Check if user exists
        response = user_table.get_item(Key={'Email': email})
        if 'Item' in response:
            return False, "User already exists."

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

# ... (verify_user remains the same) ...

# --- Routes ---

@app.route('/')
def index():
    # Landing page for everyone
    return render_template('index.html')

@app.route('/auth')
def auth():
    # Farmer Login/Signup Page
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('auth.html')

@app.route('/auth/admin')
def auth_admin():
    # Admin Login/Signup Page
    if 'user' in session:
        if session['user'].get('Role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('auth_admin.html')

@app.route('/signup/farmer', methods=['POST'])
def signup_farmer():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    success, message = create_user(email, password, name, role='farmer')
    if success:
        session['user'] = {'Email': email, 'Name': name, 'Role': 'farmer'}
        flash('Farm account created successfully!', 'success')
        send_sns_notification(f"New farmer signed up: {email}")
        return redirect(url_for('dashboard'))
    else:
        flash(message, 'error')
        return redirect(url_for('auth'))

@app.route('/signup/admin', methods=['POST'])
def signup_admin():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    success, message = create_user(email, password, name, role='admin')
    if success:
        session['user'] = {'Email': email, 'Name': name, 'Role': 'admin'}
        flash('Admin account created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        flash(message, 'error')
        return redirect(url_for('auth_admin'))

@app.route('/login/farmer', methods=['POST'])
def login_farmer():
    email = request.form['email']
    password = request.form['password']

    success, user = verify_user(email, password)
    if success:
        role = user.get('Role', 'farmer')
        if role != 'farmer':
             flash('Access Denied. Please use the Admin Portal.', 'error')
             return redirect(url_for('auth'))

        session['user'] = {'Email': user['Email'], 'Name': user['Name'], 'Role': role}
        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid credentials.', 'error')
        return redirect(url_for('auth'))

@app.route('/login/admin', methods=['POST'])
def login_admin():
    email = request.form['email']
    password = request.form['password']

    success, user = verify_user(email, password)
    if success:
        role = user.get('Role', 'farmer')
        if role != 'admin':
             flash('Access Denied. Please use the Farmer Portal.', 'error')
             return redirect(url_for('auth_admin'))

        session['user'] = {'Email': user['Email'], 'Name': user['Name'], 'Role': role}
        flash('Logged in successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        flash('Invalid credentials.', 'error')
        return redirect(url_for('auth_admin'))

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
