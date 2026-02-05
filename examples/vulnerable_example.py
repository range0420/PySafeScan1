"""
示例漏洞代码 - 用于测试PySafeScan
包含常见的Python安全漏洞
"""

import os
import subprocess
import pickle
import yaml
import sqlite3

def command_injection_vulnerable():
    """命令注入漏洞示例"""
    user_input = input("请输入命令: ")
    
    # 高危：直接执行用户输入
    os.system(user_input)  # 危险！
    
    # 高危：shell=True 允许命令注入
    subprocess.run(user_input, shell=True)  # 危险！
    
    # 相对安全：不使用shell
    subprocess.run(["ls", "-la"])  # 相对安全

def path_traversal_vulnerable():
    """路径遍历漏洞示例"""
    filename = input("请输入文件名: ")
    
    # 高危：直接使用用户输入作为路径
    with open(filename, 'r') as f:  # 危险！
        content = f.read()
    
    # 高危：拼接路径
    user_dir = input("请输入目录: ")
    filepath = os.path.join("/var/www", user_dir, "config.txt")  # 可能危险
    with open(filepath, 'r') as f:
        config = f.read()

def deserialization_vulnerable():
    """反序列化漏洞示例"""
    # 高危：pickle反序列化
    data = input("请输入序列化数据: ")
    obj = pickle.loads(data.encode())  # 危险！
    
    # 高危：yaml反序列化
    yaml_data = input("请输入YAML数据: ")
    config = yaml.load(yaml_data)  # 危险！应使用 yaml.safe_load
    
    # 安全：使用safe_load
    safe_config = yaml.safe_load(yaml_data)  # 安全

def sql_injection_vulnerable():
    """SQL注入漏洞示例（简化）"""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INT, name TEXT)")
    
    user_id = input("请输入用户ID: ")
    
    # 高危：字符串拼接SQL
    query = f"SELECT * FROM users WHERE id = {user_id}"  # 危险！
    cursor = conn.execute(query)
    
    # 安全：使用参数化查询
    safe_query = "SELECT * FROM users WHERE id = ?"
    safe_cursor = conn.execute(safe_query, (user_id,))  # 安全

def eval_vulnerable():
    """eval漏洞示例"""
    user_code = input("请输入Python代码: ")
    
    # 高危：直接执行用户代码
    result = eval(user_code)  # 非常危险！
    
    # 稍微好一点：限制globals和locals
    result = eval(user_code, {"__builtins__": None}, {})  # 仍然危险

if __name__ == "__main__":
    print("这是一个包含漏洞的示例代码文件")
    print("请勿在生产环境中使用这些函数！")
    
    # 测试调用
    command_injection_vulnerable()
