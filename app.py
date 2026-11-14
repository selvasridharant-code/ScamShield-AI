import json
import os
import re

from flask import Flask, jsonify, render_template, request
import google.generativeai as genai

app = Flask(__name__)

genai.configure(api_key=os.environ.get(
    "GEMINI_API_KEY",
    "AQ.Ab8RN6IZ8OCI_Mqj3L_09tctWjbPluhPaCS-8kan64Hy8RMWUw",
))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan-link', methods=['POST'])
def scan_link():
    data = request.get_json(silent=True) or {}
    user_input = data.get('message', '')
    if not user_input and request.form:
        user_input = request.form.get('message', '')
    if not user_input and request.data:
        try:
            raw_data = json.loads(request.data.decode('utf-8', errors='ignore'))
            user_input = raw_data.get('message', '')
        except Exception:
            pass
    user_input = (user_input or '').strip()
    
    if not user_input:
        return jsonify({"error": "No message or link provided"}), 400
    
    prompt = f"""
You are ScamShield AI, an advanced multi-modal threat and fraud detection engine. 
Analyze the following input thoroughly and instantly. The input can be a URL, a text message, an article, or a certificate/document description.

Detect if it falls under any of these categories:
1. Phishing or malicious link / Telegram scam job offer.
2. Fake academic or professional certificate / forged credentials.
3. Deepfake AI video context or misleading/fraudulent fake news article.

Provide your response strictly in the following JSON format:
{{
    "is_scam": true/false,
    "risk_level": "High Risk" / "Medium Risk" / "Safe",
    "threat_type": "Phishing Link" / "Fake Certificate" / "AI Video/Article Scam" / "Legitimate",
    "reason": "Crisp 1-2 sentence explanation tailored for users."
}}

Input to analyze: {user_input}
"""

    candidate_models = [
        "gemini-2.5-flash-lite",
        "gemini-2.5-flash",
        "gemini-3.5-flash",
        "gemini-3.8-flash",
    ]
    response = None

    for model_name in candidate_models:
        try:
            model = genai.GenerativeModel(model_name)
            response = model.generate_content(
                prompt,
                generation_config={
                    "response_mime_type": "application/json",
                    "temperature": 0.2,
                },
            )
            raw_text = _response_text(response)
            if raw_text:
                break
        except Exception:
            response = None
            continue

    raw_text = _response_text(response)
    if not raw_text:
        return jsonify({"result": _local_scan(user_input)})
    clean_text = raw_text
    if clean_text.startswith("```json"):
        clean_text = clean_text[7:]
    elif clean_text.startswith("```"):
        clean_text = clean_text[3:]
    if clean_text.endswith("```"):
        clean_text = clean_text[:-3]
    clean_text = clean_text.strip()
    
    start = clean_text.find("{")
    end = clean_text.rfind("}")
    if start >= 0 and end > start:
        clean_text = clean_text[start:end + 1]
    try:
        parsed = json.loads(clean_text)
        return jsonify({"result": parsed})
    except json.JSONDecodeError:
        return jsonify({"result": _local_scan(user_input)})


def _response_text(response):
    if not response:
        return ""
    try:
        return (response.text or "").strip()
    except Exception:
        return ""


def _local_scan(text):
    raw = text or ""
    rules = [
        (r"(telegram|whatsapp).{0,80}(job|earn|task|hr)|earn\s*[₹$]|part-time job", 48),
        (r"guaranteed\s+\d+\s*%|bit\.ly|investment platform|crypto|seed phrase", 42),
        (r"no exams|holographic|fast-track|pay\s*\$\s*\d+", 40),
        (r"\botp\b|password|verify your (account|bank)|urgent|click here", 36),
    ]
    score = 8
    for pattern, points in rules:
        if re.search(pattern, raw, re.I):
            score += points
    score = max(0, min(100, score))
    if score >= 70:
        risk = "High Risk"
    elif score >= 40:
        risk = "Medium Risk"
    else:
        risk = "Safe"
    return {
        "is_scam": score >= 40,
        "risk_level": risk,
        "risk_score": score,
        "threat_type": "Suspicious Content" if score >= 40 else "Legitimate",
        "verdict": "Suspicious patterns found" if score >= 40 else "No obvious scam signals",
        "reason": "Pattern check completed because the AI service was busy. Verify the sender before you act on this message.",
    }


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", use_reloader=False, host='0.0.0.0', port=port)

