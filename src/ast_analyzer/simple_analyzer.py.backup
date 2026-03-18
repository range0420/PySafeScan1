"""
最简单的Python AST分析器
只提取危险函数调用
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
        'os.system', 'os.popen', 'os.spawn',
        'subprocess.run', 'subprocess.call', 'subprocess.Popen',
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
                # 提取上下文信息
                context = self._get_context(node)
                
                self.results.append({
                    'filename': filename,
                    'line': node.lineno,
                    'column': node.col_offset,
                    'function': func_name,
                    'context': context,
                    'code': ast.unparse(node) if hasattr(ast, 'unparse') else str(node)
                })
                
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
        # 完全匹配
        if func_name in self.DANGEROUS_FUNCTIONS:
            return True
        
        # 部分匹配（如 subprocess. 开头的都危险）
        for dangerous in self.DANGEROUS_FUNCTIONS:
            if func_name.startswith(dangerous.split('.')[0] + '.'):
                return True
        
        return False
    
    def _get_context(self, node: ast.Call) -> str:
        """获取调用上下文（简化版）"""
        # 查找最近的父节点类型
        parent_types = []
        current = node
        
        # 这里可以扩展，暂时返回简单信息
        if hasattr(node, 'parent'):
            # 如果有父节点信息
            pass
        
        return f"调用位置: 行 {node.lineno}"

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

# 安全调用
print("Hello World")
len([1, 2, 3])
"""
    
    results = analyzer.analyze_code(test_code, "test.py")
    
    print("检测到的危险调用:")
    for result in results:
        print(f"  行 {result['line']}: {result['function']} - {result['code']}")
    
    return results

if __name__ == "__main__":
    test_simple_analyzer()
