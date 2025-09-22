from flask import Flask, request
import requests
import threading
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
    try:
        requests.post(url, data=data)
    except:
        pass

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

def check_email_exists(token, target_email):
    try:
        url = f"https://100067.connect.garena.com/game/account_security/bind:get_bind_info?app_id=100067&access_token={token}"
        response = requests.get(url, headers=COMMON_HEADERS)
        return target_email in response.text
    except:
        return False

def remove_existing_email(token):
    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
        payload = {'app_id': "100067", 'access_token': token}
        response = requests.post(url, data=payload, headers=COMMON_HEADERS)
        return response.text
    except:
        return "❌ فشل حذف الإيميل"

def monitor_process(chat_id, target_email, token):
    while chat_id in active_monitors and active_monitors[chat_id]['active']:
        try:
            if not check_email_exists(token, target_email):
                send_telegram_message(chat_id, "⚠️ الإيميل غير موجود، بدء عملية الإضافة...")
                
                remove_response = remove_existing_email(token)
                send_telegram_message(chat_id, f"🗑️ استجابة حذف الإيميل:\n{remove_response}")
                time.sleep(2)
                
                temp_email, temp_pass, temp_session = gen_temp_email()
                if temp_email:
                    send_telegram_message(chat_id, f"📧 تم إنشاء إيميل مؤقت\nEmail: {temp_email}\nPassword: {temp_pass}")
                    
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
                    
                    send_telegram_message(chat_id, f"📨 استجابة إضافة الإيميل:\n{add_response.text}")
                    
                    if add_response.status_code == 200:
                        send_telegram_message(chat_id, "⏳ في انتظار وصول رمز التحقق...")
                        
                        verification_code = None
                        start_time = time.time()
                        while time.time() - start_time < 300:
                            if not active_monitors[chat_id]['active']:
                                break
                            
                            verification_code = get_verification_code(temp_email, temp_pass, temp_session)
                            if verification_code:
                                send_telegram_message(chat_id, f"🔑 تم العثور على رمز التحقق: {verification_code}")
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
                            send_telegram_message(chat_id, f"📨 استجابة التحقق:\n{verify_response.text}")
                            
                            if verify_response.status_code == 200:
                                try:
                                    response_data = verify_response.json()
                                    verifier_token = response_data.get("verifier_token")
                                    
                                    if verifier_token:
                                        create_bind_url = "https://100067.connect.garena.com/game/account_security/bind:create_bind_request"
                                        create_payload = {
                                            'app_id': '100067',
                                            'access_token': token,
                                            'verifier_token': verifier_token,
                                            'secondary_password': "91B4D142823F7D20C5F08DF69122DE43F35F057A988D9619F6D3138485C9A203",
                                            'email': temp_email
                                        }
                                        
                                        create_response = requests.post(create_bind_url, data=create_payload, headers=COMMON_HEADERS)
                                        send_telegram_message(chat_id, f"📨 استجابة الربط النهائي:\n{create_response.text}")
                                    else:
                                        send_telegram_message(chat_id, "❌ لم يتم العثور على verifier_token")
                                except:
                                    send_telegram_message(chat_id, "❌ خطأ في تحليل استجابة التحقق")
                            else:
                                send_telegram_message(chat_id, "❌ فشل عملية التحقق")
                        else:
                            send_telegram_message(chat_id, "❌ لم يتم العثور على رمز التحقق")
                    else:
                        send_telegram_message(chat_id, "❌ فشل إضافة الإيميل")
                else:
                    send_telegram_message(chat_id, "❌ فشل إنشاء إيميل مؤقت")
            else:
                send_telegram_message(chat_id, "✅ الإيميل لا يزال موجودًا")
            
            time.sleep(3)
        except Exception as e:
            send_telegram_message(chat_id, f"❌ خطأ: {str(e)}")
            time.sleep(3)

@app.route('/webhook/telegram', methods=['POST'])
def handle_telegram_webhook():
    data = request.get_json()
    
    if not data:
        return "ok", 200
    
    message = data.get('message', {})
    chat_id = message.get('chat', {}).get('id')
    message_text = message.get('text', '')
    
    if not chat_id or not message_text:
        return "ok", 200
    
    if message_text.startswith('/start'):
        if chat_id in active_monitors:
            active_monitors[chat_id]['active'] = False
            time.sleep(1)
        
        parts = message_text.split()
        if len(parts) > 2:
            target_email = parts[1]
            token = parts[2]
            active_monitors[chat_id] = {'active': True}
            thread = threading.Thread(target=monitor_process, args=(chat_id, target_email, token))
            thread.daemon = True
            thread.start()
            send_telegram_message(chat_id, f"✅ بدء المراقبة\n📧 الإيميل: {target_email}\n🔑 التوكين: {token}")
        else:
            send_telegram_message(chat_id, "❌ استخدام: /start email token")
    
    elif message_text == '/stop':
        if chat_id in active_monitors:
            active_monitors[chat_id]['active'] = False
            send_telegram_message(chat_id, "⏹️ تم إيقاف المراقبة")
        else:
            send_telegram_message(chat_id, "⚠️ لا توجد مراقبة نشطة")
    
    return "ok", 200

if __name__ == '__main__':
    app.run()
