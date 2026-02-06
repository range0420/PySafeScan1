"""
Web应用示例 - 包含常见Web漏洞
"""

from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# 模拟数据库
def init_db():
    conn = sqlite3.connect(':memory:')
    conn.execute('CREATE TABLE users (id INT, name TEXT)')
    conn.execute("INSERT INTO users VALUES (1, 'admin')")
    conn.commit()
    return conn

@app.route('/search')
def search():
    """SQL注入漏洞示例"""
    query = request.args.get('q', '')
    conn = init_db()
    
    # 🔴 危险：SQL注入
    cursor = conn.execute(f"SELECT * FROM users WHERE name LIKE '%{query}%'")
    results = cursor.fetchall()
    
    return f"找到 {len(results)} 条记录"

@app.route('/profile')
def profile():
    """XSS漏洞示例"""
    username = request.args.get('name', 'Guest')
    
    # 🟡 危险：未转义的用户输入
    template = f"""
    <html>
    <body>
        <h1>欢迎, {username}!</h1>
        <p>您的个人资料页面</p>
    </body>
    </html>
    """
    return template

@app.route('/upload')
def upload():
    """文件上传漏洞示例"""
    filename = request.args.get('file', '')
    
    # 🟡 危险：路径遍历
    filepath = os.path.join('/uploads', filename)
    
    # 模拟文件读取
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return f"文件内容: {content[:100]}"
    except:
        return "文件读取失败"

@app.route('/safe')
def safe_endpoint():
    """安全端点示例"""
    user_id = request.args.get('id', '')
    
    # ✅ 安全：参数化查询
    conn = init_db()
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    results = cursor.fetchall()
    
    return f"安全查询结果: {results}"

if __name__ == '__main__':
    app.run(debug=True)
