"""
PySafeScan 漏洞示例文件
包含各种常见的安全漏洞
"""

import os
import sys
import pickle
import yaml
import subprocess
import sqlite3
import json
import logging

# ========== 高风险漏洞 ==========

def command_injection_demo():
    """命令注入漏洞"""
    user_cmd = input("请输入要执行的命令: ")
    # 🔴 高风险：命令注入
    os.system(user_cmd)
    
    # 同样危险的调用
    os.popen(user_cmd)
    eval("__import__('os').system('ls')")

def sql_injection_demo():
    """SQL注入漏洞"""
    user_id = input("请输入用户ID: ")
    conn = sqlite3.connect('test.db')
    
    # 🔴 高风险：SQL注入
    cursor = conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    
    # 另一种SQL注入
    query = "SELECT * FROM products WHERE name = '" + input("产品名: ") + "'"
    conn.execute(query)
    
    return cursor.fetchall()

def deserialization_demo():
    """反序列化漏洞"""
    user_data = input("输入序列化数据: ")
    
    # 🔴 高风险：pickle反序列化
    obj1 = pickle.loads(user_data.encode())
    
    # 🔴 高风险：yaml加载
    config = yaml.load(user_data, Loader=yaml.Loader)
    
    return obj1, config

def code_injection_demo():
    """代码注入漏洞"""
    user_expr = input("输入Python表达式: ")
    
    # 🔴 高风险：eval执行
    result = eval(user_expr)
    
    # 🔴 高风险：exec执行
    exec("print('危险操作')")
    
    return result

# ========== 中风险漏洞 ==========

def path_traversal_demo():
    """路径遍历漏洞"""
    filename = input("请输入文件名: ")
    
    # 🟡 中风险：路径遍历
    with open(filename, 'r') as f:
        content = f.read()
    
    # 另一种路径遍历
    full_path = "/home/user/" + filename
    os.remove(full_path)
    
    return content

def xss_demo():
    """XSS漏洞示例"""
    user_input = input("请输入评论: ")
    
    # 🟡 中风险：未转义的输出
    print(f"<div>{user_input}</div>")
    
    # Flask中的XSS风险
    from flask import escape
    # 正确做法：使用escape
    # print(escape(user_input))
    
    return user_input

def info_leak_demo():
    """信息泄露"""
    password = "secret123"
    api_key = "sk-1234567890"
    
    # 🟡 中风险：日志记录敏感信息
    logging.debug(f"用户密码: {password}")
    
    # 中风险：异常信息泄露
    try:
        risky_operation()
    except Exception as e:
        print(f"错误详情: {e}")  # 可能泄露敏感信息
    
    return password, api_key

# ========== 安全代码示例 ==========

def safe_alternatives():
    """安全代码示例"""
    
    # ✅ 安全：使用参数化查询
    user_id = input("安全用户ID: ")
    conn = sqlite3.connect(':memory:')
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    
    # ✅ 安全：使用ast.literal_eval
    import ast
    safe_expr = input("安全表达式: ")
    result = ast.literal_eval(safe_expr)
    
    # ✅ 安全：安全的文件操作
    filename = "safe_file.txt"
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            content = f.read()
    
    # ✅ 安全：使用subprocess替代os.system
    cmd = ['ls', '-la']
    subprocess.run(cmd, check=True)
    
    return cursor.fetchall()

# ========== 辅助函数 ==========

def risky_operation():
    """模拟危险操作"""
    raise ValueError("模拟错误信息，包含敏感数据: user=admin, pass=123456")

def main():
    """主函数 - 演示各种漏洞"""
    print("PySafeScan 漏洞演示程序")
    print("=" * 40)
    
    # 运行演示
    try:
        command_injection_demo()
        sql_injection_demo()
        path_traversal_demo()
        safe_alternatives()
    except Exception as e:
        print(f"演示中发生错误: {e}")

if __name__ == "__main__":
    main()
