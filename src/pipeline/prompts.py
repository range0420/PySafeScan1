# 严格同步 IRIS 原始 prompts.py 逻辑
API_LABELLING_SYSTEM_PROMPT = """You are a security expert. 
You are given a list of APIs to be labeled as potential taint sources, sinks, or APIs that propagate taints. 
Return the result as a json list with each object in the format:
{ "package": <package name>, "class": <class name>, "method": <method name>, "signature": <signature>, "sink_args": <list of arguments or `this`>, "type": <"source", "sink", or "taint-propagator"> }
"""

POSTHOC_FILTER_SYSTEM_PROMPT = """You are a security expert. 
Review the following code snippet to determine if the reported vulnerability is a True Positive.
Return JSON: {"is_vulnerable": bool, "reason": "string"}
"""

# 这是 IRIS 用于降低误报（FP）的核心字典，必须定义
POSTHOC_FILTER_HINTS = {
    "default": "Check if the data from the source is properly sanitized or if the sink is used in a safe context.",
    "sql_injection": "Check for parameter binding or prepared statements. If the input is cast to int/float, it is safe.",
    "path_injection": "Check for path normalization (e.g., os.path.abspath) or restricted directory checks.",
    "rce": "Check if the command is a hardcoded constant or restricted to a strict allowlist.",
    "xss": "Check if the output is HTML-escaped before being rendered."
}

SNIPPET_CONTEXT_SIZE = 10
