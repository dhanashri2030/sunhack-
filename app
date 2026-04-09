from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from backend.database import init_db, create_user, get_user_by_email, get_user_by_id, update_user
from backend.database import create_session, get_session, delete_session
from backend.database import create_password_reset, get_password_reset, mark_password_reset_used, update_user_password
from backend.database import save_health_reading, get_latest_reading, get_reading_history
from backend.database import add_emergency_contact, get_emergency_contacts, delete_emergency_contact
from backend.database import create_alert as db_create_alert, get_unread_alerts, get_all_alerts, mark_alert_read, mark_all_alerts_read
from backend.ml_model import analyze_health_data, calculate_anomaly_score
from backend.alerts import send_email_alert, should_send_email_alert, create_alert_message

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app, supports_credentials=True)

init_db()

def get_current_user(token):
    if not token:
        return None
    session = get_session(token)
    if not session:
        return None
    return get_user_by_id(session['user_id'])

def row_to_dict(row):
    if row is None:
        return None
    return dict(row)

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')
    age = data.get('age')
    gender = data.get('gender')

    if not all([name, email, password]):
        return jsonify({'error': 'Name, email and password are required'}), 400

    if get_user_by_email(email):
        return jsonify({'error': 'Email already registered'}), 409

    password_hash = generate_password_hash(password)
    user_id = create_user(name, email, password_hash, phone, age, gender)

    if user_id:
        return jsonify({'message': 'Account created successfully', 'user_id': user_id}), 201
    return jsonify({'error': 'Failed to create account'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'error': 'Email and password are required'}), 400

    user = get_user_by_email(email)
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid email or password'}), 401

    token = secrets.token_hex(32)
    create_session(user['id'], token)

    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user['id'],
            'name': user['name'],
            'email': user['email']
        }
    }), 200

@app.route('/api/auth/logout', methods=['GET'])
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token:
        delete_session(token)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = get_user_by_email(email)
    if not user:
        return jsonify({'message': 'If that email exists, a reset token has been generated'}), 200

    token = secrets.token_hex(16)
    from datetime import datetime, timedelta
    expires_at = datetime.utcnow() + timedelta(hours=1)
    create_password_reset(user['id'], token, expires_at)

    return jsonify({
        'message': 'If that email exists, a reset token has been generated',
        'reset_token': token
    }), 200

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return jsonify({'error': 'Token and new password are required'}), 400

    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    reset = get_password_reset(token)
    if not reset:
        return jsonify({'error': 'Invalid or expired reset token'}), 400

    from datetime import datetime
    if datetime.utcnow() > datetime.strptime(reset['expires_at'], '%Y-%m-%d %H:%M:%S.%f'):
        return jsonify({'error': 'Reset token has expired'}), 400

    password_hash = generate_password_hash(new_password)
    update_user_password(reset['user_id'], password_hash)
    mark_password_reset_used(token)

    return jsonify({'message': 'Password has been reset successfully'}), 200

@app.route('/api/dashboard', methods=['GET'])
def dashboard():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_current_user(token)

    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    latest = get_latest_reading(user['id'])
    unread = get_unread_alerts(user['id'], 10)

    return jsonify({
        'user': {
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'phone': user['phone'],
            'age': user['age'],
            'gender': user['gender']
        },
        'latest_reading': row_to_dict(latest) if latest else None,
        'unread_count': len(unread)
    }), 200

@app.route('/api/health/submit', methods=['POST'])
def submit_health():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_current_user(token)

    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    heart_rate = data.get('heart_rate')
    spo2 = data.get('spo2')
    temperature = data.get('temperature')
    bp_sys = data.get('bp_sys')
    bp_dia = data.get('bp_dia')

    if not all([heart_rate, spo2, temperature, bp_sys, bp_dia]):
        return jsonify({'error': 'All metrics are required'}), 400

    result = analyze_health_data(heart_rate, spo2, temperature, bp_sys, bp_dia)

    reading_id = save_health_reading(
        user['id'],
        heart_rate, spo2, temperature, bp_sys, bp_dia,
        result['status'], result['risk_score'], result['ai_message']
    )

    if result['status'] != 'Normal':
        alert_type = 'Critical' if result['status'] == 'Critical' else 'Warning'
        db_create_alert(user['id'], alert_type, result['ai_message'])

        if should_send_email_alert(result['status']):
            contacts = get_emergency_contacts(user['id'])
            for contact in contacts:
                if contact['email']:
                    send_email_alert(
                        contact['email'],
                        f"VitalGuard Alert - {alert_type}",
                        result['ai_message']
                    )

    return jsonify({
        'message': 'Health reading recorded',
        'reading_id': reading_id,
        'result': result
    }), 201

@app.route('/api/health/simulate', methods=['GET'])
def simulate_health():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_current_user(token)

    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from data.simulator import generate_simulation

    sim = generate_simulation()

    result = analyze_health_data(
        sim['heart_rate'], sim['spo2'],
        sim['temperature'], sim['bp_sys'], sim['bp_dia']
    )

    reading_id = save_health_reading(
        user['id'],
        sim['heart_rate'], sim['spo2'],
        sim['temperature'], sim['bp_sys'], sim['bp_dia'],
        result['status'], result['risk_score'], result['ai_message']
    )

    if result['status'] != 'Normal':
        alert_type = 'Critical' if result['status'] == 'Critical' else 'Warning'
        db_create_alert(user['id'], alert_type, result['ai_message'])

        if should_send_email_alert(result['status']):
            contacts = get_emergency_contacts(user['id'])
            for contact in contacts:
                if contact['email']:
                    send_email_alert(
                        contact['email'],
                        f"VitalGuard Alert - {alert_type}",
                        result['ai_message']
                    )

    return jsonify({
        'message': 'Simulation complete',
        'reading_id': reading_id,
        'data': {
            'heart_rate': sim['heart_rate'],
            'spo2': sim['spo2'],
            'temperature': sim['temperature'],
            'bp_sys': sim['bp_sys'],
            'bp_dia': sim['bp_dia']
        },
        'result': result
    }), 200

@app.route('/api/health/history', methods=['GET'])
def health_history():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_current_user(token)

    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    limit = request.args.get('limit', 20, type=int)
    readings = get_reading_history(user['id'], limit)

    return jsonify({
        'readings': [row_to_dict(r) for r in readings]
    }), 200

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_current_user(token)

    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    alerts = get_all_alerts(user['id'], 10)

    return jsonify({
        'alerts': [row_to_dict(a) for a in alerts]
    }), 200

@app.route('/api/alerts/mark-read', methods=['POST'])
def mark_read():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_current_user(token)

    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    alert_id = data.get('alert_id') if data else None

    if alert_id:
        mark_alert_read(alert_id, user['id'])
    else:
        mark_all_alerts_read(user['id'])

    return jsonify({'message': 'Alert(s) marked as read'}), 200

@app.route('/api/contacts', methods=['GET'])
def contacts():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_current_user(token)

    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    contacts_list = get_emergency_contacts(user['id'])

    return jsonify({
        'contacts': [row_to_dict(c) for c in contacts_list]
    }), 200

@app.route('/api/contacts/add', methods=['POST'])
def add_contact():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_current_user(token)

    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    name = data.get('name')
    relationship = data.get('relationship')
    phone = data.get('phone')
    email = data.get('email')

    if not all([name, relationship, phone]):
        return jsonify({'error': 'Name, relationship and phone are required'}), 400

    contact_id = add_emergency_contact(user['id'], name, relationship, phone, email)

    return jsonify({
        'message': 'Contact added',
        'contact_id': contact_id
    }), 201

@app.route('/api/contacts/<int:contact_id>', methods=['DELETE'])
def remove_contact(contact_id):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_current_user(token)

    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    delete_emergency_contact(contact_id, user['id'])

    return jsonify({'message': 'Contact removed'}), 200

@app.route('/api/profile', methods=['GET'])
def profile():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_current_user(token)

    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    return jsonify({
        'user': {
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'phone': user['phone'],
            'age': user['age'],
            'gender': user['gender'],
            'created_at': user['created_at']
        }
    }), 200

@app.route('/api/profile/update', methods=['PUT'])
def update_profile():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user = get_current_user(token)

    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    update_user(
        user['id'],
        name=data.get('name'),
        phone=data.get('phone'),
        age=data.get('age'),
        gender=data.get('gender')
    )

    updated_user = get_user_by_id(user['id'])

    return jsonify({
        'message': 'Profile updated',
        'user': {
            'id': updated_user['id'],
            'name': updated_user['name'],
            'email': updated_user['email'],
            'phone': updated_user['phone'],
            'age': updated_user['age'],
            'gender': updated_user['gender']
        }
    }), 200

if __name__ == '__main__':
    print("Starting VitalGuard server...")
    print("API available at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
