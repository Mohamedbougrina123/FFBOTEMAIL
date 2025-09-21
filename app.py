from flask import Flask, request, jsonify
import requests
import json
import threading
import time
import random
import string
import re
from datetime import datetime, timedelta

app = Flask(__name__)

VERIFY_TOKEN = "FFEMAIL"
PAGE_ACCESS_TOKEN = "EAANfe3CLeJEBPfx0r3oKyuvYBaKZAptFpTEIkg2b4lOcdSg6q48NV5kPYvZAZBXCYP7mxPHiWmmS0ZA0dY2eZCsmza8d4L1h0eQxBaESXRqmXHnuzyZA9MrOUaiETigCQgf2QD3YF7xoJJOwDirPEc4GzOHyunYEBvsRF07m3n1ZAihJ4enRlLsy8RRBPQzoRnTXF7fbwZDZD"
BOT_PASSWORD = "ffm-morad-mohamed"

user_data = {}
user_attempts = {}
banned_users = {}
active_loops = {}
active_auto_emails = {}

COMMON_HEADERS = {
    'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip"
}

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
                    
                    if sender_id in banned_users:
                        if datetime.now() < banned_users[sender_id]['until']:
                            send_message(sender_id, "⛔ تم حظرك لمدة 3 ساعات")
                            return "ok", 200
                        else:
                            del banned_users[sender_id]
                    
                    if sender_id not in user_data or 'authenticated' not in user_data[sender_id]:
                        if message_text == BOT_PASSWORD:
                            if sender_id not in user_data:
                                user_data[sender_id] = {}
                            user_data[sender_id]['authenticated'] = True
                            user_attempts[sender_id] = 0
                            send_message(sender_id, "✅ تم المصادقة بنجاح!\n\n/setToken [token]\n/getToken [token]\n/setEmail [email]\n/setOtp [otp]\n/RemoveEmail [token]\n/LoopEmail [seconds] [email] [token]\n/automail [seconds] [email] [token]")
                        else:
                            if sender_id not in user_attempts:
                                user_attempts[sender_id] = 0
                            user_attempts[sender_id] += 1
                            
                            if user_attempts[sender_id] >= 3:
                                banned_users[sender_id] = {'until': datetime.now() + timedelta(hours=3)}
                                send_message(sender_id, "⛔ تم حظرك لمدة 3 ساعات")
                            else:
                                send_message(sender_id, f"❌ كلمة مرور خاطئة! {user_attempts[sender_id]}/3")
                        return "ok", 200
                    
                    if message_text.startswith('/setToken'):
                        handle_set_token(sender_id, message_text)
                    elif message_text.startswith('/getToken'):
                        handle_get_token(sender_id, message_text)
                    elif message_text.startswith('/setEmail'):
                        handle_set_email(sender_id, message_text)
                    elif message_text.startswith('/setOtp'):
                        handle_set_otp(sender_id, message_text)
                    elif message_text.startswith('/RemoveEmail'):
                        handle_remove_email(sender_id, message_text)
                    elif message_text.startswith('/LoopEmail'):
                        handle_loop_email(sender_id, message_text)
                    elif message_text.startswith('/automail'):
                        handle_auto_mail(sender_id, message_text)
                    else:
                        send_message(sender_id, "❌ أمر غير معروف\n\n/setToken [token]\n/getToken [token]\n/setEmail [email]\n/setOtp [otp]\n/RemoveEmail [token]\n/LoopEmail [seconds] [email] [token]\n/automail [seconds] [email] [token]")
    
    return "ok", 200

def gen_temp_email():
    try:
        s = requests.Session()
        domains_response = s.get("https://api.mail.tm/domains")
        domains = domains_response.json()['hydra:member']
        domain = random.choice(domains)['domain']
        user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        passw = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        email = f"ffbotemail{user}@{domain}"
        acc_res = s.post("https://api.mail.tm/accounts", json={"address": email, "password": passw})
        if acc_res.status_code == 201:
            return email, passw, s
        return None, None, None
    except:
        return None, None, None

def get_verification_code(email, passw, sess):
    try:
        token_res = sess.post("https://api.mail.tm/token", json={"address": email, "password": passw})
        if token_res.status_code != 200:
            return None
        
        token = token_res.json()['token']
        headers = {"Authorization": f"Bearer {token}"}
        
        msgs_response = sess.get("https://api.mail.tm/messages", headers=headers)
        if msgs_response.status_code != 200:
            return None
        
        msgs = msgs_response.json()
        
        for msg in msgs.get('hydra:member', []):
            download_url = msg.get('downloadUrl')
            
            if download_url:
                download_response = sess.get(f"https://api.mail.tm{download_url}", headers=headers)
                
                if download_response.status_code == 200:
                    content = download_response.text
                    
                    lines = content.split('\n')
                    body_started = False
                    message_body = ""
                    
                    for line in lines:
                        if line.strip() == '' and not body_started:
                            body_started = True
                            continue
                        if body_started:
                            message_body += line + '\n'
                   
                    code_match = re.search(r'للمتابعة، يرجى إدخال رمز التحقق أدناه\s*(\d{6,8})', message_body)
                    if code_match:
                        return code_match.group(1)
                    
                    code_match = re.search(r'رمز التحقق\s*(\d{6,8})', message_body)
                    if code_match:
                        return code_match.group(1)
                    
                    codes = re.findall(r'\b\d{6,8}\b', message_body)
                    if codes:
                        return codes[0]
        
        return None
    except:
        return None

def handle_auto_mail(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 4:
        send_message(sender_id, "/automail [seconds] [email] [token]")
        return
    
    try:
        interval = int(parts[1])
        target_email = parts[2]
        token = parts[3]
        
        if sender_id in active_auto_emails:
            active_auto_emails[sender_id]['active'] = False
        
        active_auto_emails[sender_id] = {'active': True}
        thread = threading.Thread(target=auto_mail_process, args=(sender_id, interval, target_email, token))
        thread.daemon = True
        thread.start()
        
        send_message(sender_id, f"✅ بدء المراقبة التلقائية كل {interval} ثانية\n📧 {target_email}")
    except ValueError:
        send_message(sender_id, "❌ يرجى إدخال رقم صحيح للثواني")

def auto_mail_process(sender_id, interval, target_email, token):
    temp_email, temp_pass, temp_session = None, None, None
    
    while sender_id in active_auto_emails and active_auto_emails[sender_id]['active']:
        try:
            url = f"https://100067.connect.garena.com/game/account_security/bind:get_bind_info?app_id=100067&access_token={token}"
            response = requests.get(url, headers=COMMON_HEADERS)
            
            if target_email not in response.text:
                if not temp_email:
                    temp_email, temp_pass, temp_session = gen_temp_email()
                    if temp_email:
                        send_message(sender_id, f"📧 تم إنشاء إيميل مؤقت\nEmail: {temp_email}\nPassword: {temp_pass}")
                        
                        add_email_url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
                        payload = {
                            'app_id': '100067',
                            'access_token': token,
                            'email': temp_email,
                            'locale': 'ar_EG'
                        }
                        
                        headers = COMMON_HEADERS.copy()
                        headers['Accept'] = "application/json"
                        add_response = requests.post(add_email_url, data=payload, headers=headers)
                        
                        send_message(sender_id, f"📨 استجابة إضافة الإيميل:\n{add_response.text}")
                        
                        if add_response.status_code == 200:
                            send_message(sender_id, "⏳ في انتظار وصول رمز التحقق...")
                            
                            verification_code = None
                            start_time = time.time()
                            while time.time() - start_time < 300:
                                if not active_auto_emails[sender_id]['active']:
                                    break
                                
                                verification_code = get_verification_code(temp_email, temp_pass, temp_session)
                                if verification_code:
                                    send_message(sender_id, f"🔑 تم العثور على رمز التحقق: {verification_code}")
                                    break
                                
                                time.sleep(10)
                            
                            if verification_code:
                                verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
                                verify_payload = {
                                    'app_id': '100067',
                                    'access_token': token,
                                    'otp': verification_code,
                                    'email': temp_email
                                }
                                
                                verify_response = requests.post(verify_url, data=verify_payload, headers=COMMON_HEADERS)
                                send_message(sender_id, f"📨 استجابة التحقق:\n{verify_response.text}")
                                
                                if verify_response.status_code == 200:
                                    try:
                                        response_data = verify_response.json()
                                        verifier_token = response_data.get("verifier_token")
                                        
                                        if verifier_token:
                                            create_bind_request(sender_id, token, temp_email, verifier_token)
                                        else:
                                            send_message(sender_id, "❌ لم يتم العثور على verifier_token في الاستجابة")
                                    except:
                                        send_message(sender_id, "❌ خطأ في تحليل استجابة التحقق")
                                else:
                                    send_message(sender_id, "❌ فشل عملية التحقق")
                            else:
                                send_message(sender_id, "❌ لم يتم العثور على رمز التحقق بعد 5 دقائق")
                        else:
                            send_message(sender_id, "❌ فشل إضافة الإيميل المؤقت")
                    else:
                        send_message(sender_id, "❌ فشل إنشاء إيميل مؤقت")
                else:
                    send_message(sender_id, "⚠️ تم حذف ربط الاستعادة الخاص بك!")
            
            time.sleep(interval)
        except Exception as e:
            send_message(sender_id, f"❌ خطأ: {str(e)}")
            time.sleep(interval)

def handle_set_token(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "/setToken [token]")
        return
    
    token = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['token'] = token
    
    url = f"https://100067.connect.garena.com/game/account_security/bind:get_bind_info?app_id=100067&access_token={token}"
    
    try:
        response = requests.get(url, headers=COMMON_HEADERS)
        send_message(sender_id, f"{response.text}")
    except Exception as e:
        send_message(sender_id, f"❌ {str(e)}")

def handle_get_token(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "/getToken [token]")
        return
    
    token = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['token'] = token
    
    send_message(sender_id, f"{token}")

def handle_set_email(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "/setEmail [email]")
        return
    
    email = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['email'] = email
    
    token = user_data[sender_id].get('token', '')
    if not token:
        send_message(sender_id, "❌ /setToken [token]")
        return
    
    url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
    payload = {
        'app_id': '100067',
        'access_token': token,
        'email': email,
        'locale': 'ar_EG'
    }
    
    headers = COMMON_HEADERS.copy()
    headers['Accept'] = "application/json"
    
    try:
        response = requests.post(url, data=payload, headers=headers)
        send_message(sender_id, f"{response.text}")
    except Exception as e:
        send_message(sender_id, f"❌ {str(e)}")

def handle_set_otp(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "/setOtp [otp]")
        return
    
    otp = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['otp'] = otp
    
    token = user_data[sender_id].get('token', '')
    email = user_data[sender_id].get('email', '')
    
    if not token:
        send_message(sender_id, "❌ /setToken [token]")
        return
    
    if not email:
        send_message(sender_id, "❌ /setEmail [email]")
        return
    
    url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
    payload = {
        'app_id': '100067',
        'access_token': token,
        'otp': otp,
        'email': email
    }
    
    try:
        response = requests.post(url, data=payload, headers=COMMON_HEADERS)
        response_text = response.text
        
        if response.status_code == 200:
            try:
                response_data = response.json()
                verifier_token = response_data.get("verifier_token")
                
                if verifier_token:
                    create_bind_request(sender_id, token, email, verifier_token)
                else:
                    send_message(sender_id, f"{response_text}")
            except:
                send_message(sender_id, f"{response_text}")
        else:
            send_message(sender_id, f"{response_text}")
            
    except Exception as e:
        send_message(sender_id, f"❌ {str(e)}")

def handle_remove_email(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "/RemoveEmail [token]")
        return
    
    token = parts[1]
    url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
    payload = {
        'app_id': "100067",
        'access_token': token
    }
    
    try:
        response = requests.post(url, data=payload, headers=COMMON_HEADERS)
        send_message(sender_id, f"{response.text}")
    except Exception as e:
        send_message(sender_id, f"❌ {str(e)}")

def handle_loop_email(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 4:
        send_message(sender_id, "/LoopEmail [seconds] [email] [token]")
        return
    
    try:
        interval = int(parts[1])
        email = parts[2]
        token = parts[3]
        
        if sender_id in active_loops:
            active_loops[sender_id]['active'] = False
        
        active_loops[sender_id] = {'active': True}
        thread = threading.Thread(target=email_loop, args=(sender_id, interval, email, token))
        thread.daemon = True
        thread.start()
        
        send_message(sender_id, f"✅ بدء المراقبة كل {interval} ثانية\n📧 {email}")
    except ValueError:
        send_message(sender_id, "❌ يرجى إدخال رقم صحيح للثواني")

def email_loop(sender_id, interval, email, token):
    while sender_id in active_loops and active_loops[sender_id]['active']:
        try:
            url = f"https://100067.connect.garena.com/game/account_security/bind:get_bind_info?app_id=100067&access_token={token}"
            response = requests.get(url, headers=COMMON_HEADERS)
            
            if email not in response.text:
                send_message(sender_id, "⚠️ تم حذف ربط الاستعادة الخاص بك!")
            
            time.sleep(interval)
        except Exception as e:
            time.sleep(interval)

def create_bind_request(sender_id, token, email, verifier_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:create_bind_request"
    payload = {
        'app_id': '100067',
        'access_token': token,
        'verifier_token': verifier_token,
        'secondary_password': "91B4D142823F7D20C5F08DF69122DE43F35F057A988D9619F6D3138485C9A203",
        'email': email
    }
    
    try:
        response = requests.post(url, data=payload, headers=COMMON_HEADERS)
        send_message(sender_id, f"{response.text}")
    except Exception as e:
        send_message(sender_id, f"❌ {str(e)}")

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
        print(f"❌ {e}")

if __name__ == '__main__':
    app.run()
