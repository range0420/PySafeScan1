import re, requests
from src.utils.prompt_utils import generate_message_list

DEEPSEEK_API_KEY = "sk-86b3b532876344e38b1412989fec387f" 
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"

def verify_vulnerability(labeled_code, api_context, cwe_id):
    messages = generate_message_list(labeled_code, api_context, prompt_cwe=cwe_id)
    payload = {"model": "deepseek-chat", "messages": messages, "temperature": 0.0}
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {DEEPSEEK_API_KEY}"}

    try:
        response = requests.post(f"{DEEPSEEK_BASE_URL}/chat/completions", headers=headers, json=payload, timeout=60)
        content = response.json()["choices"][0]["message"]["content"]
        is_vuln = "$$ VULNERABILITY: YES" in content.upper()
        match = re.search(r"explanation:(.*?)\$\$", content, re.DOTALL | re.IGNORECASE)
        return {"is_vulnerable": is_vuln, "explanation": match.group(1).strip() if match else content}
    except Exception as e:
        return {"is_vulnerable": False, "explanation": f"API Error: {e}"}
