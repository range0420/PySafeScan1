import json
from openai import OpenAI
import os

class IRISBrain:
    def __init__(self):
        # 确保你已经 export DEEPSEEK_API_KEY
        self.api_key = os.getenv("DEEPSEEK_API_KEY")
        self.client = OpenAI(api_key=self.api_key, base_url="https://api.deepseek.com")

    def stage2_infer_specs(self, candidates):
        """
        对应流程图：第二阶段 - LLM 规范推断
        """
        prompt = f"""
        [IRIS Phase 2: Specification Inference]
        Candidate APIs: {list(candidates)}
        
        Task: You are a security expert. Identify 'Sources' and 'Sinks' for Python security auditing.
        - Sources: Functions that return user-controlled data (e.g., get, request.args, input).
        - Sinks: Functions that perform dangerous operations (e.g., execute, eval, system, write).
        
        Return ONLY a valid JSON object:
        {{"sources": ["api_name1", "api_name2"], "sinks": ["api_name3"]}}
        """
        try:
            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[{"role": "user", "content": prompt}],
                response_format={'type': 'json_object'}
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            print(f"⚠️ Stage 2 LLM Error: {e}")
            return {"sources": [], "sinks": []}

    def stage4_verify_path(self, code, path_info):
        """
        对应流程图：第四阶段 - LLM 上下文验证 (终审)
        """
        prompt = f"""
        [IRIS Phase 4: Contextual Verification]
        A static analysis tool found a potential taint flow to Sink: '{path_info['sink']}' on line {path_info['line']}.
        
        Full Code for Context:
        {code}
        
        Strict Verdict Rules:
        1. If the input data is clearly sanitized (e.g., using int(), isdigit(), or regex), return is_vulnerable: false.
        2. If the data is a constant/hardcoded string, return is_vulnerable: false.
        3. If raw user input can reach the Sink without validation, return is_vulnerable: true.
        
        Return JSON: {{"is_vulnerable": bool, "reasoning": "Explain why"}}
        """
        try:
            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[{"role": "user", "content": prompt}],
                response_format={'type': 'json_object'}
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            print(f"⚠️ Stage 4 LLM Error: {e}")
            return {"is_vulnerable": False, "reasoning": "LLM error"}
