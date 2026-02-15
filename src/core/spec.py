import os
import yaml

def load_all_rules():
    """全自动规则加载器"""
    combined_specs = {}
    # 动态定位 rules 目录
    base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    rules_path = os.path.join(base_path, "rules")
    
    if os.path.exists(rules_path):
        for filename in os.listdir(rules_path):
            if filename.endswith(".yaml"):
                with open(os.path.join(rules_path, filename), 'r') as f:
                    data = yaml.safe_load(f)
                    if data:
                        for k, v in data.items():
                            combined_specs[k] = {
                                "sinks": v.get("sinks", []),
                                "sanitizers": v.get("sanitizers", []),
                                "danger_desc": v.get("desc", "")
                            }
    return combined_specs

SECURITY_SPECS = load_all_rules()
POTENTIAL_SOURCES = ["input", "request.args", "request.form", "os.getenv", "f.read", "sys.argv"]
