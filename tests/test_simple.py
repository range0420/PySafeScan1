"""
简单测试
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ast_analyzer.simple_analyzer import SimplePythonAnalyzer

def test_analyzer_basic():
    """基础测试"""
    analyzer = SimplePythonAnalyzer()
    
    test_code = """
import os
os.system("echo test")
x = eval("1+1")
    """
    
    results = analyzer.analyze_code(test_code, "test.py")
    
    assert len(results) >= 2, f"应该至少找到2个危险调用，实际找到 {len(results)}"
    
    functions_found = [r['function'] for r in results]
    assert 'os.system' in functions_found, "应该找到 os.system"
    assert 'eval' in functions_found, "应该找到 eval"
    
    print("✓ 基础测试通过")

def test_analyzer_file(tmp_path):
    """文件测试"""
    analyzer = SimplePythonAnalyzer()
    
    # 创建测试文件
    test_file = tmp_path / "test_code.py"
    test_file.write_text("""
import subprocess
subprocess.run(["ls", "-la"])
    """)
    
    results = analyzer.analyze_file(str(test_file))
    
    assert len(results) == 1, f"应该找到1个危险调用，实际找到 {len(results)}"
    assert results[0]['function'] == 'subprocess.run'
    
    print("✓ 文件测试通过")

if __name__ == "__main__":
    test_analyzer_basic()
    print("所有测试通过!")
