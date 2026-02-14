import ast
import os
from typing import List, Dict

class SimplePythonAnalyzer:
    """强化版Python代码分析器：支持深度函数溯源与作用域追踪"""
    
    # 扩展后的危险 API 列表
    DANGEROUS_FUNCTIONS = {
        'exec', 'eval', 'execute', 'compile', 'open', '__import__',
        'os.system', 'os.popen', 'os.spawn', 'subprocess.run',
        'subprocess.call', 'subprocess.Popen', 'pickle.loads',
        'yaml.load', 'sqlite3.connect', 'cursor.execute', 'conn.execute',
        'requests.get', 'requests.post', 'requests.request',
        'urllib.request.urlopen'
    }
    
    def __init__(self):
        self.results = []
        self._current_function_stack = [] 

    def analyze_file(self, file_path: str) -> List[Dict]:
        if not os.path.exists(file_path): return []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            return self.analyze_code(code, file_path)
        except Exception as e:
            print(f"分析文件 {file_path} 时出错: {e}")
            return []

    def analyze_code(self, code: str, filename: str = "<string>") -> List[Dict]:
        self.results = []
        # 初始化作用域栈，最底层是全局
        self._current_function_stack = ["Global"] 
        try:
            tree = ast.parse(code)
            self._visit_node(tree, filename) 
            return self.results
        except SyntaxError:
            return []
        except Exception as e:
            print(f"解析 AST 失败: {e}")
            return []

    def _visit_node(self, node: ast.AST, filename: str):
        """
        深度优先遍历 AST，维护当前所在的函数/类作用域
        """
        # --- 入栈逻辑 ---
        # 记录函数名或类名
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._current_function_stack.append(node.name)
        elif isinstance(node, ast.ClassDef):
            # 类作用域加上前缀，方便 Patcher 识别是类内方法
            self._current_function_stack.append(node.name)

        # --- 核心分析逻辑 ---
        if isinstance(node, ast.Call):
            self._analyze_call(node, filename)

        # 递归访问所有子节点
        for child in ast.iter_child_nodes(node):
            self._visit_node(child, filename)

        # --- 出栈逻辑 ---
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self._current_function_stack.pop()

    def _analyze_call(self, node: ast.Call, filename: str):
        try:
            func_name = self._get_function_name(node.func)
            if not func_name: return

            # 判定标准：
            # 1. 直接命中危险函数列表
            is_danger_api = self._is_dangerous_function(func_name)
            
            # 2. 参数中包含可疑的变量拼接 (f-string, +, 或是直接引用变量)
            has_suspicious_arg = any(isinstance(arg, (ast.JoinedStr, ast.BinOp, ast.Name)) for arg in node.args)
            
            # 3. 排除一些绝对安全的内置常用函数，剩下的自定义函数如果有可疑参数，也报出来给 AI 分析
            is_generic_func = "." not in func_name and func_name not in ["print", "len", "dict", "list", "range", "str", "int"]

            if is_danger_api or (is_generic_func and has_suspicious_arg):
                # 提取当前所属函数
                current_scope = self._current_function_stack[-1]
                
                # 使用 ast.unparse 获取原始代码行 (Python 3.9+)
                code_snippet = ast.unparse(node)

                result = {
                    'file': filename, 
                    'line': node.lineno,
                    'api': code_snippet, 
                    'function': current_scope, # Patcher 定位核心：当前所属函数名
                    'api_name': func_name,     
                    'column': getattr(node, 'col_offset', 0)
                }
                
                # 去重处理
                if result not in self.results:
                    self.results.append(result)
        except Exception:
            pass

    def _get_function_name(self, node) -> str:
        """支持获取 Name (eval) 和 Attribute (os.system) 类型的函数名"""
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute): return self._get_attribute_name(node)
        return ""

    def _get_attribute_name(self, node: ast.Attribute) -> str:
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name): parts.append(current.id)
        parts.reverse()
        return ".".join(parts)

    def _is_dangerous_function(self, func_name: str) -> bool:
        """
        危险 API 匹配引擎
        """
        # 模糊匹配 .execute (适用于 DB 游标等)
        if func_name.endswith('.execute') or func_name == 'execute': return True
        
        # 完全匹配
        if func_name in self.DANGEROUS_FUNCTIONS: return True

        # 模块前缀匹配 (处理 subprocess.run, os.popen 等)
        if '.' in func_name:
            parts = func_name.split('.')
            for dangerous in self.DANGEROUS_FUNCTIONS:
                if '.' not in dangerous: continue
                d_parts = dangerous.split('.')
                
                # 如果主模块名一致 (如 os 或 subprocess)
                if parts[0] == d_parts[0]:
                    # 排除 os.path 等安全路径操作
                    if parts[0] == 'os' and len(parts) > 1 and parts[1].startswith('path'):
                        return False
                    # 匹配模块下的关键危险函数族
                    if d_parts[1].startswith(('spawn', 'popen', 'run', 'call')):
                        return parts[1].startswith(d_parts[1][:4])
                    return func_name == dangerous
        return False
