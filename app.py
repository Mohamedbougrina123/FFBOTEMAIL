from flask import Flask, request, jsonify
import requests
import json
import threading
import time
from datetime import datetime, timedelta

app = Flask(__name__)

VERIFY_TOKEN = "FFEMAIL"
PAGE_ACCESS_TOKEN = "EAANfe3CLeJEBPfx0r3oKyuvYBaKZAptFpTEIkg2b4lOcdSg6q48NV5kPYvZAZBXCYP7mxPHiWmmS0ZA0dY2eZCsmza8d4L1h0eQxBaESXRqmXHnuzyZA9MrOUaiETigCQgf2QD3YF7xoJJOwDirPEc4GzOHyunYEBvsRF07m3n1ZAihJ4enRlLsy8RRBPQzoRnTXF7fbwZDZD"
BOT_PASSWORD = "ffm-morad-mohamed"

user_data = {}
user_attempts = {}
banned_users = {}
active_loops = {}

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
                    
                    # التحقق من الحظر
                    if sender_id in banned_users:
                        if datetime.now() < banned_users[sender_id]['until']:
                            send_message(sender_id, "⛔ تم حظرك لمدة 3 ساعات بسبب محاولات دخول فاشلة")
                            return "ok", 200
                        else:
                            del banned_users[sender_id]
                    
                    # التحقق من كلمة المرور
                    if sender_id not in user_data or 'authenticated' not in user_data[sender_id]:
                        if message_text == BOT_PASSWORD:
                            if sender_id not in user_data:
                                user_data[sender_id] = {}
                            user_data[sender_id]['authenticated'] = True
                            user_attempts[sender_id] = 0
                            send_message(sender_id, "✅ تم المصادقة بنجاح!\n\n📋 الأوامر المتاحة:\n/setToken [token]\n/getToken [token]\n/setEmail [email]\n/setOtp [otp]\n/RemoveEmail [token]\n/LoopEmail [seconds] [email] [token]")
                        else:
                            if sender_id not in user_attempts:
                                user_attempts[sender_id] = 0
                            user_attempts[sender_id] += 1
                            
                            if user_attempts[sender_id] >= 3:
                                banned_users[sender_id] = {'until': datetime.now() + timedelta(hours=3)}
                                send_message(sender_id, "⛔ تم حظرك لمدة 3 ساعات بسبب محاولات دخول فاشلة")
                            else:
                                send_message(sender_id, f"❌ كلمة مرور خاطئة! المحاولة {user_attempts[sender_id]}/3")
                        return "ok", 200
                    
                    # معالجة الأوامر بعد المصادقة
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
                    else:
                        send_message(sender_id, "❌ أمر غير معروف\n\n📋 الأوامر المتاحة:\n/setToken [token]\n/getToken [token]\n/setEmail [email]\n/setOtp [otp]\n/RemoveEmail [token]\n/LoopEmail [seconds] [email] [token]")
    
    return "ok", 200

def handle_set_token(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "📝 الاستخدام:\n/setToken [token]")
        return
    
    token = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['token'] = token
    
    url = f"https://100067.connect.garena.com/game/account_security/bind:get_bind_info?app_id=100067&access_token={token}"
    
    try:
        response = requests.get(url, headers=COMMON_HEADERS)
        send_message(sender_id, f"📨 الاستجابة:\n{response.text}")
    except Exception as e:
        send_message(sender_id, f"❌ خطأ:\n{str(e)}")

def handle_get_token(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "📝 الاستخدام:\n/getToken [token]")
        return
    
    token = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['token'] = token
    
    send_message(sender_id, f"✅ تم استلام التوكن:\n{token}")

def handle_set_email(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "📝 الاستخدام:\n/setEmail [email]")
        return
    
    email = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['email'] = email
    
    token = user_data[sender_id].get('token', '')
    if not token:
        send_message(sender_id, "❌ يرجى تعيين التوكن أولاً باستخدام\n/setToken [token]")
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
        send_message(sender_id, f"📨 استجابة إرسال OTP:\n{response.text}")
    except Exception as e:
        send_message(sender_id, f"❌ خطأ في إرسال OTP:\n{str(e)}")

def handle_set_otp(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "📝 الاستخدام:\n/setOtp [otp]")
        return
    
    otp = parts[1]
    if sender_id not in user_data:
        user_data[sender_id] = {}
    user_data[sender_id]['otp'] = otp
    
    token = user_data[sender_id].get('token', '')
    email = user_data[sender_id].get('email', '')
    
    if not token:
        send_message(sender_id, "❌ يرجى تعيين التوكن أولاً باستخدام\n/setToken [token]")
        return
    
    if not email:
        send_message(sender_id, "❌ يرجى تعيين الإيميل أولاً باستخدام\n/setEmail [email]")
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
                    send_message(sender_id, f"✅ تم التحقق من OTP ولكن لم يتم العثور على verifier_token:\n{response_text}")
            except ValueError:
                send_message(sender_id, f"📨 استجابة التحقق من OTP:\n{response_text}")
        else:
            send_message(sender_id, f"❌ فشل التحقق من OTP:\n{response_text}")
            
    except Exception as e:
        send_message(sender_id, f"❌ خطأ في التحقق من OTP:\n{str(e)}")

def handle_remove_email(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 2:
        send_message(sender_id, "📝 الاستخدام:\n/RemoveEmail [token]")
        return
    
    token = parts[1]
    url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
    payload = {
        'app_id': "100067",
        'access_token': token
    }
    
    try:
        response = requests.post(url, data=payload, headers=COMMON_HEADERS)
        send_message(sender_id, f"📨 استجابة إزالة الإيميل:\n{response.text}")
    except Exception as e:
        send_message(sender_id, f"❌ خطأ في إزالة الإيميل:\n{str(e)}")

def handle_loop_email(sender_id, message_text):
    parts = message_text.split()
    if len(parts) < 4:
        send_message(sender_id, "📝 الاستخدام:\n/LoopEmail [seconds] [email] [token]")
        return
    
    try:
        interval = int(parts[1])
        email = parts[2]
        token = parts[3]
        
        # إيقاف أي حلقة نشطة سابقة لنفس المستخدم
        if sender_id in active_loops:
            active_loops[sender_id]['active'] = False
        
        # بدء حلقة جديدة
        active_loops[sender_id] = {'active': True}
        thread = threading.Thread(target=email_loop, args=(sender_id, interval, email, token))
        thread.daemon = True
        thread.start()
        
        send_message(sender_id, f"✅ بدء مراقبة الإيميل كل {interval} ثانية\n📧 الإيميل: {email}")
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
        send_message(sender_id, f"📨 استجابة ربط الإيميل:\n{response.text}")
    except Exception as e:
        send_message(sender_id, f"❌ خطأ في ربط الإيميل:\n{str(e)}")

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
        print(f"❌ خطأ في إرسال الرسالة: {e}")

if __name__ == '__main__':
    app.run(debug=True, port=5000)
