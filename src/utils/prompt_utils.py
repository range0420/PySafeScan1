def generate_iris_prompt(source_node, sink_node, code_slice, cwe_id):
    """
    参考 IRIS 论文设计的验证提示词
    """
    system_prompt = "You are a path verification assistant for a static analysis tool."
    
    user_content = f"""Vulnerability Verification (CWE-{cwe_id})
    
[Data Flow Evidence]:
The static analyzer traced a potential flow:
Source: {source_node}
Sink: {sink_node}

[Code Context (Sliced)]:
{code_slice}

[Task]:
Verify if the data flow is VALID and EXPLOITABLE.
- Is there any sanitizer (e.g., escape, basename) that breaks the flow?
- Is the source actually controlled by a remote user?
- If the logic is safe, report NO.

Format: $$ vulnerability: <YES/NO> | explanation: <Specific path analysis> $$
"""
    return [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_content}]
