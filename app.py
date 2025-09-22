from flask import Flask, request
import requests
import time
import random
import string
import re

app = Flask(__name__)

BOT_TOKEN = "8061516463:AAFey2ud8QNBFRKLyyVHyLGuGNMz4ThDvQU"
active_monitors = {}

COMMON_HEADERS = {
    'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip"
}

def send_telegram_message(chat_id, message_text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {"chat_id": chat_id, "text": message_text}
    try: requests.post(url, data=data)
    except: pass

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
        if acc_res.status_code == 201: return email, passw, s
        return None, None, None
    except: return None, None, None

def get_verification_code(email, passw, sess):
    try:
        token_res = sess.post("https://api.mail.tm/token", json={"address": email, "password": passw})
        if token_res.status_code != 200: return None
        token = token_res.json()['token']
        headers = {"Authorization": f"Bearer {token}"}
        msgs_response = sess.get("https://api.mail.tm/messages", headers=headers)
        if msgs_response.status_code != 200: return None
        msgs = msgs_response.json()
        for msg in msgs.get('hydra:member', []):
            download_url = msg.get('downloadUrl')
            if download_url:
                download_response = sess.get(f"https://api.mail.tm{download_url}", headers=headers)
                if download_response.status_code == 200:
                    content = download_response.text
                    code_match = re.search(r'للمتابعة، يرجى إدخال رمز التحقق أدناه\s*(\d{6,8})', content)
                    if code_match: return code_match.group(1)
                    code_match = re.search(r'رمز التحقق\s*(\d{6,8})', content)
                    if code_match: return code_match.group(1)
                    codes = re.findall(r'\b\d{6,8}\b', content)
                    if codes: return codes[0]
        return None
    except: return None

def get_current_email(token):
    try:
        url = f"https://100067.connect.garena.com/game/account_security/bind:get_bind_info?app_id=100067&access_token={token}"
        response = requests.get(url, headers=COMMON_HEADERS)
        email_match = re.search(r'"email":"([^"]+)"', response.text)
        return email_match.group(1) if email_match else None
    except: return None

def remove_email(token):
    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
        payload = {'app_id': "100067", 'access_token': token}
        response = requests.post(url, data=payload, headers=COMMON_HEADERS)
        return response.text
    except: return "فشل الحذف"

def add_email(token, email):
    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
        payload = {'app_id': '100067', 'access_token': token, 'email': email, 'locale': 'ar_EG'}
        headers = COMMON_HEADERS.copy()
        headers['Accept'] = "application/json"
        response = requests.post(url, data=payload, headers=headers)
        return response.text
    except: return "فشل الإضافة"

def verify_otp(token, email, otp):
    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
        payload = {'app_id': '100067', 'access_token': token, 'otp': otp, 'email': email}
        response = requests.post(url, data=payload, headers=COMMON_HEADERS)
        return response.text
    except: return "فشل التحقق"

def create_bind(token, email, verifier_token):
    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:create_bind_request"
        payload = {
            'app_id': '100067',
            'access_token': token,
            'verifier_token': verifier_token,
            'secondary_password': "91B4D142823F7D20C5F08DF69122DE43F35F057A988D9619F6D3138485C9A203",
            'email': email
        }
        response = requests.post(url, data=payload, headers=COMMON_HEADERS)
        return response.text
    except: return "فشل الربط"

def monitor_process(chat_id, target_email, token):
    while chat_id in active_monitors and active_monitors[chat_id]:
        try:
            current_email = get_current_email(token)
            
            if current_email == target_email:
                send_telegram_message(chat_id, f"✅ الإيميل صحيح: {current_email}")
            else:
                send_telegram_message(chat_id, f"⚠️ الإيميل مختلف: {current_email}")
                
                remove_response = remove_email(token)
                send_telegram_message(chat_id, f"🗑️ حذف الإيميل: {remove_response}")
                time.sleep(2)
                
                temp_email, temp_pass, temp_session = gen_temp_email()
                if temp_email:
                    send_telegram_message(chat_id, f"📧 إيميل جديد: {temp_email}\n🔑 كلمة السر: {temp_pass}")
                    
                    add_response = add_email(token, temp_email)
                    send_telegram_message(chat_id, f"📨 إضافة الإيميل: {add_response}")
                    
                    if "success" in add_response.lower() or "200" in add_response:
                        send_telegram_message(chat_id, "⏳ جاري انتظار الرمز...")
                        
                        for _ in range(30):
                            if not active_monitors.get(chat_id): break
                            otp = get_verification_code(temp_email, temp_pass, temp_session)
                            if otp:
                                send_telegram_message(chat_id, f"🔑 الرمز: {otp}")
                                
                                verify_response = verify_otp(token, temp_email, otp)
                                send_telegram_message(chat_id, f"📨 تحقق الرمز: {verify_response}")
                                
                                if "verifier_token" in verify_response:
                                    verifier_match = re.search(r'"verifier_token":"([^"]+)"', verify_response)
                                    if verifier_match:
                                        verifier_token = verifier_match.group(1)
                                        bind_response = create_bind(token, temp_email, verifier_token)
                                        send_telegram_message(chat_id, f"📨 الربط النهائي: {bind_response}")
                                break
                            time.sleep(10)
                        else:
                            send_telegram_message(chat_id, "❌ انتهى وقت انتظار الرمز")
                else:
                    send_telegram_message(chat_id, "❌ فشل إنشاء إيميل")
            
            time.sleep(3)
        except Exception as e:
            time.sleep(3)

@app.route('/webhook/telegram', methods=['POST'])
def handle_telegram_webhook():
    data = request.get_json()
    if not data: return "ok", 200
    
    message = data.get('message', {})
    chat_id = message.get('chat', {}).get('id')
    message_text = message.get('text', '')
    
    if not chat_id or not message_text: return "ok", 200
    
    if message_text.startswith('/start'):
        parts = message_text.split()
        if len(parts) > 2:
            target_email = parts[1]
            token = parts[2]
            active_monitors[chat_id] = True
            monitor_process(chat_id, target_email, token)
        else:
            send_telegram_message(chat_id, "❌ /start email token")
    
    elif message_text == '/stop':
        active_monitors[chat_id] = False
        send_telegram_message(chat_id, "⏹️ توقف المراقبة")
    
    return "ok", 200

if __name__ == '__main__':
        app.run()
