import subprocess
import os
import json

def extract_flow_paths(db_path):
    """
    参考 IRIS Stage 2: 提取从 Source 到 Sink 的完整数据流证据
    """
    ql_path = "modules/iris_dataflow.ql"
    output_json = "flow_results.json"
    
    # 运行 CodeQL 数据流查询
    cmd = f"codeql query run --database={db_path} {ql_path} --output=results.bqrs && " \
          f"codeql bqrs decode results.bqrs --format=json --output={output_json}"
    subprocess.run(cmd, shell=True, check=True)
    
    if os.path.exists(output_json):
        with open(output_json, 'r') as f:
            return json.load(f)
    return []
