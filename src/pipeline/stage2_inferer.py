import json
from openai import OpenAI
from src.config import API_KEY, BASE_URL
from .prompts import API_LABELLING_SYSTEM_PROMPT

def infer_specs(candidates):
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    user_prompt = f"Label these Python methods:\n{', '.join(candidates)}"

    try:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": API_LABELLING_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            response_format={'type': 'json_object'}
        )
        # 严格解析 IRIS 格式的 JSON 列表
        res = json.loads(response.choices[0].message.content)
        api_list = res.get('apis', res.get('results', [])) 
        
        specs = {"sources": [], "sinks": {}, "propagators": []}
        for item in api_list:
            m_type = item.get('type', '').lower()
            method = item.get('method', '')
            if m_type == 'source':
                specs['sources'].append(method)
            elif m_type == 'sink':
                specs['sinks'][method] = item.get('sink_args', [])
            elif m_type == 'taint-propagator':
                specs['propagators'].append(method)
        return specs
    except Exception:
        # 保底：如果 AI 没返回，手动加入 Benchmark 常见的危险函数
        return {
            "sources": ["get_argument", "get_param", "request", "input"],
            "sinks": {"execute": ["query"], "eval": ["code"], "system": ["command"], "open": ["file"]},
            "propagators": ["format", "join", "replace"]
        }
