import ast
import jedi
import os
from asttokens import ASTTokens

def get_enhanced_context(file_path, line_number):
    try:
        abs_path = os.path.abspath(file_path)
        with open(abs_path, 'r', encoding='utf-8') as f:
            source_code = f.read()

        atok = ASTTokens(source_code, parse=True)
        auxiliary_context = []

        # 1. 提取漏洞所在行的原始代码 (置顶作为 Patcher 定位锚点)
        source_lines = source_code.splitlines()
        vulnerable_line_content = ""
        if 0 < line_number <= len(source_lines):
            vulnerable_line_content = source_lines[line_number - 1].strip()

        # 2. 提取相关 Import
        imports = [atok.get_text(n) for n in ast.walk(atok.tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        if imports:
            auxiliary_context.append("# Imports\n" + "\n".join(imports))

        # 3. 提取函数/类上下文
        for node in ast.walk(atok.tree):
            if hasattr(node, 'first_token') and node.first_token.start[0] <= line_number <= node.last_token.end[0]:
                if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                    auxiliary_context.append(f"# Local Context ({node.name})\n{atok.get_text(node)}")
                    break

        # 4. 重新组合：特征行必须在前
        final_output = []
        if vulnerable_line_content:
            final_output.append(vulnerable_line_content)
        if auxiliary_context:
            final_output.extend(auxiliary_context)

        return "\n\n".join(final_output)
    except Exception as e:
        return f"Retrieval Error: {str(e)}"
