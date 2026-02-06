"""
最简单的Python AST分析器
最终修复版本：正确的函数检测逻辑
"""

import ast
import os
from typing import List, Dict

class SimplePythonAnalyzer:
    """简单Python代码分析器"""
    
    # 常见危险函数列表
    DANGEROUS_FUNCTIONS = {
        'exec', 'eval', 'compile', 
        'open', '__import__',
        'os.system', 'os.popen', 'os.spawn', 'os.spawnl', 'os.spawnle', 'os.spawnlp', 'os.spawnlpe', 'os.spawnv', 'os.spawnve', 'os.spawnvp', 'os.spawnvpe',
        'subprocess.run', 'subprocess.call', 'subprocess.Popen', 'subprocess.check_call', 'subprocess.check_output',
        'pickle.loads', 'pickle.load',
        'yaml.load', 'yaml.safe_load',
        'marshal.loads',
        'sqlite3.connect.execute',  # 简化的SQL注入检测
    }
    
    def __init__(self):
        self.results = []
    
    def analyze_file(self, file_path: str) -> List[Dict]:
        """分析单个Python文件"""
        if not os.path.exists(file_path):
            print(f"文件不存在: {file_path}")
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            return self.analyze_code(code, file_path)
            
        except Exception as e:
            print(f"分析文件 {file_path} 时出错: {e}")
            return []
    
    def analyze_directory(self, directory_path: str) -> List[Dict]:
        """分析整个目录"""
        if not os.path.exists(directory_path):
            print(f"目录不存在: {directory_path}")
            return []
        
        all_results = []
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    results = self.analyze_file(file_path)
                    all_results.extend(results)
        
        return all_results
    
    def analyze_code(self, code: str, filename: str = "<string>") -> List[Dict]:
        """分析代码字符串"""
        self.results = []
        
        try:
            tree = ast.parse(code)
            self._visit_tree(tree, filename)
            return self.results
            
        except SyntaxError as e:
            print(f"语法错误 {filename}: {e}")
            return []
    
    def _visit_tree(self, tree: ast.AST, filename: str):
        """遍历AST树"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._analyze_call(node, filename)
    
    def _analyze_call(self, node: ast.Call, filename: str):
        """分析函数调用"""
        try:
            # 获取函数名
            func_name = self._get_function_name(node.func)
            if not func_name:
                return
            
            # 检查是否是危险函数
            if self._is_dangerous_function(func_name):
                # 提取代码片段
                try:
                    code_snippet = ast.unparse(node) if hasattr(ast, 'unparse') else self._safe_unparse(node)
                except:
                    code_snippet = str(node)
                
                # 创建统一的数据结构
                result = {
                    # 向后兼容的字段
                    'filename': filename,
                    'line': node.lineno,
                    'column': node.col_offset if hasattr(node, 'col_offset') else 0,
                    'function': func_name,
                    'context': f"行 {node.lineno}",
                    'code': code_snippet,
                    
                    # 新的统一字段（供deepseek_api使用）
                    'file': filename,
                    'api': code_snippet,  # 使用完整代码片段作为api字段
                    'function_name': func_name,  # 纯函数名
                }
                
                self.results.append(result)
                
        except Exception as e:
            print(f"分析调用节点时出错: {e}")
    
    def _get_function_name(self, node) -> str:
        """提取函数名"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # 处理 os.system 这种形式
            return self._get_attribute_name(node)
        return ""
    
    def _get_attribute_name(self, node: ast.Attribute) -> str:
        """提取属性访问形式的函数名"""
        parts = []
        current = node
        
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        
        if isinstance(current, ast.Name):
            parts.append(current.id)
        
        parts.reverse()
        return ".".join(parts)
    
    def _is_dangerous_function(self, func_name: str) -> bool:
        """检查是否是危险函数"""
        # 1. 完全匹配
        if func_name in self.DANGEROUS_FUNCTIONS:
            return True
        
        # 2. 检查函数是否包含模块前缀
        if '.' not in func_name:
            # 没有模块前缀的函数只进行完全匹配
            return False
        
        # 3. 智能部分匹配
        func_parts = func_name.split('.')
        
        for dangerous in self.DANGEROUS_FUNCTIONS:
            # 如果危险函数没有模块前缀（如 'open', 'eval'）
            if '.' not in dangerous:
                # 对于没有模块前缀的危险函数，只进行完全匹配
                continue
            
            # 危险函数有模块前缀（如 'os.system', 'subprocess.run'）
            dangerous_parts = dangerous.split('.')
            
            # 检查模块名是否相同
            if func_parts[0] != dangerous_parts[0]:
                continue
            
            # 相同模块下的函数族检测
            
            # 特殊情况：os模块
            if func_parts[0] == 'os':
                # os.path.* 函数是安全的
                if len(func_parts) > 1 and func_parts[1].startswith('path'):
                    return False
                
                # os.spawn 家族
                if dangerous_parts[1].startswith('spawn'):
                    return func_parts[1].startswith('spawn')
                
                # os.popen 家族
                if dangerous_parts[1].startswith('popen'):
                    return func_parts[1].startswith('popen')
                
                # 其他os函数需要精确匹配
                return func_name == dangerous
            
            # 对于其他模块（如subprocess），同一模块下的调用都视为危险
            # 例如：subprocess.run 危险，那么 subprocess.call, subprocess.Popen 也危险
            return True
        
        return False
    
    def _safe_unparse(self, node: ast.AST) -> str:
        """安全地反解析AST节点"""
        try:
            if hasattr(ast, 'unparse'):
                return ast.unparse(node)
            else:
                # Python 3.8及以下版本的简单实现
                if isinstance(node, ast.Call):
                    func_name = self._get_function_name(node.func)
                    args = []
                    for arg in node.args:
                        if isinstance(arg, ast.Constant):
                            args.append(repr(arg.value))
                        else:
                            args.append("...")
                    return f"{func_name}({', '.join(args)})"
                return str(node)
        except:
            return str(node)

def test_simple_analyzer():
    """测试函数"""
    analyzer = SimplePythonAnalyzer()
    
    # 测试代码
    test_code = """
import os
import subprocess

# 危险调用
os.system("ls -la")  # 命令注入风险
user_input = input("文件名: ")
open(user_input, 'r')  # 路径遍历风险
os.spawnlp(os.P_WAIT, "ls", "ls")  # spawn家族

# 安全调用
os.path.join("a", "b")
print("Hello World")
len([1, 2, 3])
"""
    
    results = analyzer.analyze_code(test_code, "test.py")
    
    print("检测到的危险调用:")
    for result in results:
        print(f"  行 {result['line']}: {result['function']}")
        print(f"      API字段: {result.get('api', 'N/A')}")
        print(f"      文件字段: {result.get('file', 'N/A')}")
    
    return results

if __name__ == "__main__":
    test_simple_analyzer()
