import sys
import os
import json
from openai import OpenAI
from src.core.analyzer import analyze_file

class DeepSeekIrisAuditor:
    def __init__(self):
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key: 
            raise ValueError("❌ 环境变量 DEEPSEEK_API_KEY 未设置")
        self.client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com/v1")

    def audit(self, vuln_type, code_slice, spec):
        path_str = "\n".join([f"Step {i+1}: {c}" for i, c in enumerate(code_slice)])
        prompt = f"""你现在是专业的代码审计员。
[任务]: 分析代码切片是否存在漏洞。
[特别注意]: 
1. 如果路径中出现 [CLEAN] 步骤，说明污染变量在到达执行点前已被硬编码的常数覆盖，此时必须判定为 false。
2. 如果路径中出现 [SAFE] 步骤，说明已脱敏，判定为 false。
3. 如果 [LOGIC] 步骤提供了足够的防御（如 isalnum），判定为 false。

[代码切片]:
{path_str}

严格 JSON 返回：{{'is_vulnerable': bool, 'reasoning': str, 'fix_code': str}}
"""
        response = self.client.chat.completions.create(
            model="deepseek-coder",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        return json.loads(response.choices[0].message.content)

def log_finding(file_path, res):
    """完善系统：将发现的漏洞持久化到日志"""
    with open("audit_log.txt", "a", encoding="utf-8") as f:
        f.write(f"\n{'='*50}\n")
        f.write(f"文件: {file_path}\n原因: {res['reasoning']}\n修复: {res['fix_code']}\n")

def main(target):
    potentials = analyze_file(target)
    if not potentials: return
    
    auditor = DeepSeekIrisAuditor()
    for p in potentials:
        res = auditor.audit(p['type'], p['slice'], p['spec'])
        if res['is_vulnerable']:
            print(f"  ❌ 确认为漏洞! 原因: {res['reasoning'][:100]}...")
            log_finding(target, res)
        else:
            print(f"  ✅ 判定为误报。")

if __name__ == "__main__":
    if len(sys.argv) > 1: main(sys.argv[1])
