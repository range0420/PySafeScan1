import ast
import re

class UniversalTaintAnalyzer(ast.NodeVisitor):
    def __init__(self, source_code):
        self.source_code = source_code
        self.lines = source_code.splitlines()
        self.tainted_vars = {}  # 修改为字典：变量名 -> 定义处的代码行
        self.potentials = []
        self.sanitizers = {'escape', 'quote', 'int', 'float', 'hex', 'strip'}

    def _get_full_name(self, node):
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._get_full_name(node.value)}.{node.attr}"
        return ""

    def is_generalized_source(self, node):
        full_name = self._get_full_name(node)
        patterns = ['request.', 'cookie', 'header', 'environ', 'payload', 'data', 'input', 'argv']
        return any(p in full_name.lower() for p in patterns)

    def get_taint_reason(self, node):
        """递归检查并返回导致污染的根源描述"""
        if node is None: return None
        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            return f"variable '{node.id}' (defined at line {self.tainted_vars[node.id]})"
        if self.is_generalized_source(node):
            return f"external source '{self._get_full_name(node)}'"
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call)):
            # 简化逻辑：只要子节点有毒就返回
            for child in ast.iter_child_nodes(node):
                reason = self.get_taint_reason(child)
                if reason: return reason
        return None

    def visit_Assign(self, node):
        reason = self.get_taint_reason(node.value)
        for target in node.targets:
            t_name = None
            if isinstance(target, ast.Name): t_name = target.id
            elif isinstance(target, (ast.Subscript, ast.Attribute)) and isinstance(target.value, ast.Name):
                t_name = target.value.id
            
            if t_name:
                if reason:
                    self.tainted_vars[t_name] = node.lineno
                else:
                    self.tainted_vars.pop(t_name, None)
        self.generic_visit(node)

    def visit_Call(self, node):
        reason = self.get_taint_reason(node)
        if reason:
            func_name = self._get_full_name(node.func)
            safe_builtins = {'print', 'len', 'type', 'isinstance', 'str', 'append'}
            if func_name.lower() not in safe_builtins:
                # 关键改进：不仅给当前行，还要给污染源定义行
                source_line = 0
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                        source_line = self.tainted_vars[arg.id]

                self.potentials.append({
                    'line': node.lineno,
                    'type': 'Taint_Propagation_Risk',
                    'spec': f"Data from {reason} reached sink '{func_name}'",
                    'slice': self._build_smart_slice(source_line, node.lineno)
                })
        self.generic_visit(node)

    def _build_smart_slice(self, start_line, end_line):
        """跨行切片：让 AI 同时看到污点定义和 Sink 调用"""
        lines = []
        if start_line > 0:
            lines.append(f"--- [Taint Source Line {start_line}] ---")
            lines.append(self.lines[max(0, start_line-1)])
            lines.append("...")
        
        lines.append(f"--- [Sink Execution Line {end_line}] ---")
        start = max(0, end_line - 3)
        end = min(len(self.lines), end_line + 2)
        lines.extend(self.lines[start:end])
        return "\n".join(lines)

def analyze_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # 强化版翻译：处理更多嵌套情况
            code = re.sub(r'f"(.*?)\{(.*?)\}(.*?)"', r'("\1" + str(\2) + "\3")', code)
            code = re.sub(r"f'(.*?)\{(.*?)\}(.*?)'", r"('\1' + str(\2) + '\3')", code)
            tree = ast.parse(code)

        analyzer = UniversalTaintAnalyzer(code)
        analyzer.visit(tree)
        return analyzer.potentials
    except Exception:
        return []
