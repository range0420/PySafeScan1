"""
简单测试文件 - 用于快速测试
"""

import os

def simple_vuln():
    """简单的命令注入"""
    cmd = input("输入命令: ")
    os.system(cmd)  # 危险！

def safe_function():
    """安全函数"""
    print("这是一个安全函数")

if __name__ == "__main__":
    simple_vuln()
    safe_function()
