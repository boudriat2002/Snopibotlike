from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import data_pb2  # ملف protobuf الذي أنشأته عبر protoc
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

app = Flask(__name__)

# إعداد logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)

# دالة لقراءة الحسابات من ملف acc.txt
def read_accounts(file_path):
    with open(file_path, "r") as file:
        content = file.read()
        return json.loads(content)

# دالة لتشفير البيانات باستخدام AES
def encrypt_data(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    return cipher.encrypt(padded_data).hex()

# دالة لجلب JWT Token من الـ API
def get_jwt_token(uid, password):
    url = f"https://gpl-jwt.vercel.app/get?uid={uid}&password={password}"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return uid, response.json().get("token")
        return uid, None
    except Exception as e:
        logging.error(f"خطأ جلب JWT لـ {uid}: {e}")
        return uid, None

# دالة لإرسال الطلب إلى السيرفر
def send_request(url, encrypted_data, jwt_token):
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB48",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Host": "clientbp.ggblueshark.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }
    try:
        return requests.post(url, headers=headers, data=bytes.fromhex(encrypted_data))
    except Exception as e:
        logging.error(f"خطأ أثناء إرسال الطلب: {e}")
        return None

# Endpoint API
@app.route("/like", methods=["GET"])
def like_endpoint():
    try:
        request_id = int(request.args.get("id"))
        request_code = request.args.get("code")

        if not request_id or not request_code:
            return jsonify({"error": "يجب إرسال id و code"}), 400

        # قراءة الحسابات
        accounts = read_accounts("acc.txt")

        # Key و IV
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

        # عنوان السيرفر
        url = "https://clientbp.ggblueshark.com/LikeProfile"

        # إنشاء protobuf
        request_data = data_pb2.RequestData()
        request_data.id = request_id
        request_data.code = request_code

        data_bytes = request_data.SerializeToString()
        encrypted_data = encrypt_data(data_bytes, key, iv)

        # جلب JWTs
        jwt_tokens = {}
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_jwt_token, uid, pwd) for uid, pwd in accounts.items()]
            for future in as_completed(futures):
                uid, token = future.result()
                if token:
                    jwt_tokens[uid] = token

        # إرسال الطلبات
        results = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(send_request, url, encrypted_data, token): uid for uid, token in jwt_tokens.items()}
            for future in as_completed(futures):
                uid = futures[future]
                resp = future.result()
                if resp:
                    results.append({
                        "uid": uid,
                        "status_code": resp.status_code,
                        "response_text": resp.text
                    })
                else:
                    results.append({
                        "uid": uid,
                        "status": "failed"
                    })

        return jsonify({
            "request_id": request_id,
            "request_code": request_code,
            "results": results
        })

    except Exception as e:
        logging.error(f"خطأ في الـ API: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
