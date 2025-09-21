from flask import Flask, request, jsonify
import requests
import json

app = Flask(__name__)

VERIFY_TOKEN = "your_verify_token_here"
PAGE_ACCESS_TOKEN = "YOUR_PAGE_ACCESS_TOKEN_HERE"

user_data = {}

@app.route('/webhook', methods=['GET'])
def verify_webhook():
    mode = request.args.get('hub.mode')
    token = request.args.get('hub.verify_token')
    challenge = request.args.get('hub.challenge')
    
    if mode and token:
        if mode == 'subscribe' and token == VERIFY_TOKEN:
            return challenge
        else:
            return "Verification failed", 403
    
    return "Invalid parameters", 400

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    data = request.get_json()
    
    if data.get('object') == 'page':
        for entry in data.get('entry', []):
            for messaging_event in entry.get('messaging', []):
                if messaging_event.get('message'):
                    sender_id = messaging_event['sender']['id']
                    message_text = messaging_event['message'].get('text', '')
                    
                    if message_text.startswith('/setToken'):
                        handle_set_token(sender_id, message_text)
                    elif message_text.startswith('/getToken'):
                        handle_get_token(sender_id, message_text)
                    elif message_text.startswith('/setEmail'):
                        handle_set_email(sender_id, message_text)
                    elif message_text.startswith('/setOtp'):
                        handle_set_otp(sender_id, message_text)
                    else:
                        send_message(sender_id, "Unknown command. Available: /setToken, /getToken, /setEmail, /setOtp")
    
    return "ok", 200

def handle_set_token(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "Usage: /setToken [token]")
        return
    
    token = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['token'] = token
    
    url = f"https://100067.connect.garena.com/game/account_security/bind:get_bind_info?app_id=100067&access_token={token}"
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }
    
    try:
        response = requests.get(url, headers=headers)
        send_message(sender_id, f"Response: {response.text}")
    except Exception as e:
        send_message(sender_id, f"Error: {str(e)}")

def handle_get_token(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "Usage: /getToken [token]")
        return
    
    token = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['token'] = token
    
    send_message(sender_id, f"Token received: {token}")

def handle_set_email(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "Usage: /setEmail [email]")
        return
    
    email = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['email'] = email
    
    token = user_data[sender_id].get('token', '')
    if not token:
        send_message(sender_id, "Please set token first using /setToken")
        return
    
    url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
    payload = {
        'app_id': '100067',
        'access_token': token,
        'email': email,
        'locale': 'ar_EG'
    }
    
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Accept': "application/json"
    }
    
    try:
        response = requests.post(url, data=payload, headers=headers)
        send_message(sender_id, f"OTP sent response: {response.text}")
    except Exception as e:
        send_message(sender_id, f"Error sending OTP: {str(e)}")

def handle_set_otp(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "Usage: /setOtp [otp]")
        return
    
    otp = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['otp'] = otp
    
    token = user_data[sender_id].get('token', '')
    email = user_data[sender_id].get('email', '')
    
    if not token:
        send_message(sender_id, "Please set token first using /setToken")
        return
    
    if not email:
        send_message(sender_id, "Please set email first using /setEmail")
        return
    
    url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
    payload = {
        'app_id': '100067',
        'access_token': token,
        'otp': otp,
        'email': email
    }
    
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }
    
    try:
        response = requests.post(url, data=payload, headers=headers)
        response_text = response.text
        
        if response.status_code == 200:
            try:
                response_data = response.json()
                verifier_token = response_data.get("verifier_token")
                
                if verifier_token:
                    create_bind_request(sender_id, token, email, verifier_token)
                else:
                    send_message(sender_id, f"OTP verified but no verifier_token: {response_text}")
            except ValueError:
                send_message(sender_id, f"OTP verification response: {response_text}")
        else:
            send_message(sender_id, f"OTP verification failed: {response_text}")
            
    except Exception as e:
        send_message(sender_id, f"Error verifying OTP: {str(e)}")

def create_bind_request(sender_id, token, email, verifier_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:create_bind_request"
    payload = {
        'app_id': '100067',
        'access_token': token,
        'verifier_token': verifier_token,
        'secondary_password': "91B4D142823F7D20C5F08DF69122DE43F35F057A988D9619F6D3138485C9A203",
        'email': email
    }
    
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }
    
    try:
        response = requests.post(url, data=payload, headers=headers)
        send_message(sender_id, f"Bind request response: {response.text}")
    except Exception as e:
        send_message(sender_id, f"Error creating bind request: {str(e)}")

def send_message(recipient_id, message_text):
    url = f"https://graph.facebook.com/v19.0/me/messages?access_token={PAGE_ACCESS_TOKEN}"
    headers = {'Content-Type': 'application/json'}
    data = {
        "recipient": {"id": recipient_id},
        "message": {"text": message_text}
    }
    
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
    except Exception as e:
        print(f"Message sending error: {e}")

if __name__ == '__main__':
    app.run()
