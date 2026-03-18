import ast

class TaintTracker(ast.NodeVisitor):
    def __init__(self, sources, sinks, propagators, logger=None):
        self.sources = [s.lower() for s in sources]
        self.sinks_spec = {k.lower(): [str(a).lower() for a in v] for k, v in sinks.items()}
        self.propagators = [p.lower() for p in propagators]
        # IRIS 初始种子：request 相关属性
        self.tainted_vars = {'request', 'params', 'args', 'form', 'data', 'user_input'}
        self.found_paths = []

    def visit_Assign(self, node):
        # 1. 检查右值是否调用了 Propagator 或 Source
        is_gen = False
        if isinstance(node.value, ast.Call):
            func_name = self._get_func_name(node.value)
            if func_name:
                # 如果调用了 Source 函数
                if func_name.lower() in self.sources: is_gen = True
                # 如果调用了 Propagator 且参数中有受污染变量
                if func_name.lower() in self.propagators:
                    if any(self._is_node_tainted(a) for a in node.value.args): is_gen = True

        # 2. 检查普通的变量传递
        rhs_names = [n.id.lower() for n in ast.walk(node.value) if isinstance(n, ast.Name)]
        if any(name in self.tainted_vars for name in rhs_names): is_gen = True

        # 3. 更新 Target
        for target in node.targets:
            name = self._get_func_name(target)
            if name:
                if is_gen: self.tainted_vars.add(name.lower())
                elif name.lower() in self.tainted_vars: self.tainted_vars.remove(name.lower())
        
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self._get_func_name(node.func)
        if name and name.lower() in self.sinks_spec:
            # 只要任意参数受污染，且符合 IRIS 的 Sink 逻辑就记录
            if any(self._is_node_tainted(arg) for arg in node.args):
                self.found_paths.append({"sink": name, "line": node.lineno})
        self.generic_visit(node)

    def _get_func_name(self, node):
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute): return node.attr
        return None

    def _is_node_tainted(self, node):
        for n in ast.walk(node):
            name = self._get_func_name(n)
            if name and name.lower() in self.tainted_vars: return True
        return False
