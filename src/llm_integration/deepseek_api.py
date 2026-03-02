import os
import json
from openai import OpenAI

class DeepSeekIrisAuditor:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        if not self.api_key:
            raise ValueError("❌ 未找到 DEEPSEEK_API_KEY 环境变量")
        self.client = OpenAI(api_key=self.api_key, base_url="https://api.deepseek.com/v1")

    def audit_path(self, vuln_type, code_slice, spec):
        """神经审计：判断切片路径是否具备可利用性"""
        path_str = "\n".join([f"Step {i+1}: {code}" for i, code in enumerate(code_slice)])
        
        prompt = f"""
你现在是 IRIS 神经符号审计引擎。请根据代码切片分析漏洞。

[漏洞类型]: {vuln_type}
[类型描述]: {spec['danger_desc']}

[代码路径切片]:
{path_str}

[任务]:
1. 判断 Step 1 的污染源数据是否能在没有任何有效过滤的情况下到达最后一步。
2. 如果中间有 isalnum() 或 shlex.quote() 等过滤逻辑，判定为 false。
3. 严格 JSON 返回。

格式：
{{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "详细的逻辑推导",
  "fix_code": "修复后的完整代码块"
}}
"""
        try:
            response = self.client.chat.completions.create(
                model="deepseek-coder",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.1
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            return {"is_vulnerable": False, "reasoning": f"AI 审计失败: {str(e)}", "fix_code": ""}
