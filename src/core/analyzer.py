import ast
import os
from src.core.spec import SECURITY_SPECS, POTENTIAL_SOURCES

class IrisPowerSlicer:
    def __init__(self, tree, source_code):
        self.tree = tree
        self.lines = source_code.splitlines()

    def extract_vars(self, node):
        """深度提取变量、属性和字典访问"""
        v = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                v.add(n.id)
            elif isinstance(n, (ast.Attribute, ast.Subscript)):
                v.add(ast.unparse(n))
        return v

    def is_dangerous_call(self, node):
        """精准 Sink 匹配：支持参数过滤（如 shell=True）"""
        try:
            call_name = ast.unparse(node.func)
        except: return False, None
        
        # 特殊逻辑：针对 subprocess 的参数感知
        if "subprocess" in call_name:
            is_shell_true = any(
                kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True 
                for kw in node.keywords
            )
            if not is_shell_true: return False, None

        for v_type, spec in SECURITY_SPECS.items():
            if any(sink in call_name for sink in spec['sinks']):
                return True, (v_type, spec)
        return False, None

    def get_slice(self, sink_node, spec):
        """终极切片算法：追踪、洗白、逻辑捕获"""
        path_slice = []
        target_taints = self.extract_vars(sink_node)
        
        # 逆序扫描 AST 节点
        nodes = sorted(list(ast.walk(self.tree)), key=lambda x: getattr(x, 'lineno', 0), reverse=True)

        for node in nodes:
            if not hasattr(node, 'lineno') or node.lineno >= sink_node.lineno:
                continue

            # 1. 赋值与洗白追踪
            if isinstance(node, ast.Assign):
                targets = {ast.unparse(t) for t in node.targets}
                if targets & target_taints:
                    # 常量覆盖洗白 (Killer Assignment)
                    if isinstance(node.value, (ast.Constant, ast.Num, ast.Str)):
                        path_slice.insert(0, f"[CLEAN] 常量覆盖(洗白): {ast.unparse(node)}")
                        target_taints -= targets
                        continue
                    
                    # 净化器过滤
                    if isinstance(node.value, ast.Call) and any(s in ast.unparse(node.value.func) for s in spec['sanitizers']):
                        path_slice.insert(0, f"[SAFE] 净化器拦截: {ast.unparse(node)}")
                        target_taints -= targets
                        continue
                    
                    path_slice.insert(0, f"Line {node.lineno}: {self.lines[node.lineno-1].strip()}")
                    target_taints -= targets
                    target_taints.update(self.extract_vars(node.value))

            # 2. 外部引入感知 (Import)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                path_slice.insert(0, f"[IMPORT] 外部定义: {ast.unparse(node)}")

            # 3. 逻辑校验点
            elif isinstance(node, (ast.If, ast.Assert)):
                if self.extract_vars(node.test) & target_taints:
                    path_slice.insert(0, f"[LOGIC] 校验逻辑: {ast.unparse(node.test)}")

            # 4. 污染源识别 (Source)
            elif isinstance(node, ast.Call):
                if any(src in ast.unparse(node) for src in POTENTIAL_SOURCES):
                    path_slice.insert(0, f"[SOURCE] 污染源确认: {ast.unparse(node)}")

        path_slice.append(f"[SINK] 危险点执行: {ast.unparse(sink_node)}")
        return path_slice

def analyze_file(file_path):
    if not os.path.exists(file_path): return []
    with open(file_path, "r", encoding="utf-8") as f:
        source = f.read()
    try:
        tree = ast.parse(source)
    except: return []

    slicer = IrisPowerSlicer(tree, source)
    results = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            is_danger, spec_info = slicer.is_dangerous_call(node)
            if is_danger:
                v_type, spec = spec_info
                trace = slicer.get_slice(node, spec)
                # 只有包含 SOURCE 的路径才有审计价值
                if any("[SOURCE]" in step for step in trace):
                    results.append({'type': v_type, 'spec': spec, 'slice': trace, 'line': node.lineno})
    return results
