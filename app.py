from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import data_pb2  # ملف data_pb2.py الذي تم إنشاؤه بواسطة protoc
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

# قراءة الحسابات من ملف
def read_accounts(file_path):
    with open(file_path, "r") as file:
        return json.load(file)  # يتوقع List of dicts

# تشفير البيانات
def encrypt_data(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    return cipher.encrypt(padded_data).hex()

# جلب JWT Token
def get_jwt_token(uid, password):
    url = f"https://gpl-jwt.vercel.app/get?uid={uid}&password={password}"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            logging.info(f"✅ تم جلب التوكن لـ {uid}")
            return uid, response.json().get("token")
        logging.warning(f"⚠️ فشل لجلب التوكن لـ {uid}")
        return uid, None
    except Exception as e:
        logging.error(f"❌ خطأ في جلب التوكن لـ {uid}: {e}")
        return uid, None

# إرسال الطلب للسيرفر
def send_request(url, encrypted_data, jwt_token):
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Host": "clientbp.ggblueshark.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }
    try:
        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_data))
        return response
    except Exception as e:
        logging.error(f"❌ خطأ في إرسال الطلب: {e}")
        return None

# المسار الرئيسي في Flask
@app.route("/like", methods=["GET"])
def like_profile():
    try:
        # أخذ المدخلات من الطلب
        request_id = request.args.get("id")
        request_code = request.args.get("code")

        if not request_id or not request_code:
            return jsonify({"error": "يجب إرسال id و code"}), 400

        request_id = int(request_id)

        # قراءة الحسابات
        accounts = read_accounts("acc.txt")

        # إعدادات التشفير
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

        # إنشاء الرسالة وتشفيرها
        request_data = data_pb2.RequestData()
        request_data.id = request_id
        request_data.code = request_code
        data_bytes = request_data.SerializeToString()
        encrypted_data = encrypt_data(data_bytes, key, iv)
        logging.info("🔐 تم التشفير بنجاح.")

        # جلب التوكنات باستخدام الـ ThreadPool
        jwt_tokens = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(get_jwt_token, acc["uid"], acc["password"]) for acc in accounts]
            for future in as_completed(futures):
                uid, token = future.result()
                if token:
                    jwt_tokens[uid] = token

        # إرسال الطلبات
        url = "https://clientbp.ggblueshark.com/LikeProfile"
        results = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_uid = {
                executor.submit(send_request, url, encrypted_data, token): uid
                for uid, token in jwt_tokens.items()
            }

            for future in as_completed(future_to_uid):
                uid = future_to_uid[future]
                response = future.result()
                if response:
                    results.append({
                        "uid": uid,
                        "status_code": response.status_code,
                        "response_text": response.text
                    })
                else:
                    results.append({
                        "uid": uid,
                        "status": "failed"
                    })

        return jsonify({
            "request_id": request_id,
            "request_code": request_code,
            "success_count": len([r for r in results if r.get("status_code") == 200]),
            "results": results
        })

    except Exception as e:
        logging.error(f"❌ خطأ في المسار /like: {e}")
        return jsonify({"error": str(e)}), 500

# تشغيل السيرفر
if __name__ == "__main__":
    app.run(debug=True, port=5000))
