import os, json, subprocess, requests, re

class IrisPipeline:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.deepseek.com/v1"

    def extract_paths(self, db_path):
        ql_path = "modules/iris_engine.ql"
        output_bqrs = "results.bqrs"
        output_json = "results.json"
        
        # 1. 运行符号分析
        subprocess.run(["codeql", "query", "run", f"--database={db_path}", ql_path, f"--output={output_bqrs}"], check=True)
        # 2. 解码 JSON
        subprocess.run(["codeql", "bqrs", "decode", output_bqrs, "--format=json", f"--output={output_json}"], check=True)
        
        if not os.path.exists(output_json): return []
        with open(output_json, 'r') as f:
            data = json.load(f)
            
        paths = []
        # 解析 #select 字段，提取 Source 和 Sink 的位置
        if "#select" in data and "tuples" in data["#select"]:
            for t in data["#select"]["tuples"]:
                try:
                    # t[0] 是 sink, t[1] 是 source
                    # URL 格式通常为: file:/home/user/test.py:10:5:10:20
                    sink_raw = t[0]["url"].split(":")
                    source_raw = t[1]["url"].split(":")
                    
                    paths.append({
                        "file": sink_raw[1],
                        "sink_line": int(sink_raw[2]),
                        "source_line": int(source_raw[2])
                    })
                except: continue
        return paths

    def get_program_slice(self, file_path, source_ln, sink_ln, window=5):
        """IRIS Stage 3: 程序切片逻辑"""
        if not os.path.exists(file_path): return ""
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        start = max(1, min(source_ln, sink_ln) - window)
        end = min(len(lines), max(source_ln, sink_ln) + window)
        
        res = []
        for i in range(start - 1, end):
            prefix = ">> " if (i + 1) in [source_ln, sink_ln] else "   "
            res.append(f"{prefix}{i+1}: {lines[i]}")
        return "".join(res)

    def verify_path(self, code_slice, cwe_id):
        # 严格执行 IRIS 论文的推理指令
        prompt = f"""[IRIS Verifier]
Verify if user-controlled input from the 'source' line reaches the 'sink' line.
[Code Slice]:
{code_slice}
[Task]: If any sanitizer, regex check, or type-cast blocks this flow, output NO.
FORMAT: $$ vulnerability: <YES/NO> | explanation: <reason> $$"""
        try:
            res = requests.post(f"{self.base_url}/chat/completions",
                                headers={"Authorization": f"Bearer {self.api_key}"},
                                json={"model": "deepseek-chat", "messages": [{"role": "user", "content": prompt}], "temperature": 0.0})
            return res.json()["choices"][0]["message"]["content"]
        except: return "ERROR"
