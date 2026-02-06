#!/usr/bin/env python3
"""
PySafeScan 演示脚本
展示完整的AI安全扫描功能
"""
import os
import sys
import subprocess
import json

def print_header(text):
    """打印标题"""
    print("\n" + "="*60)
    print(f"📌 {text}")
    print("="*60)

def run_command(cmd, capture=True):
    """运行命令"""
    print(f"$ {cmd}")
    if capture:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(f"⚠️  {result.stderr}")
        return result.returncode == 0, result.stdout
    else:
        return subprocess.call(cmd, shell=True) == 0, ""

def check_api_key():
    """检查API密钥"""
    if os.getenv("DEEPSEEK_API_KEY"):
        return True
    if os.path.exists(".env"):
        with open(".env", "r") as f:
            if "DEEPSEEK_API_KEY" in f.read():
                return True
    return False

def main():
    print("🚀 PySafeScan - AI赋能的Python代码安全扫描演示")
    print("版本: 0.2.0 | 集成DeepSeek AI分析")
    print("=" * 60)
    
    # 1. 显示版本信息
    print_header("显示版本信息")
    run_command("python src/cli.py version")
    
    # 2. 查看帮助
    print_header("查看帮助文档")
    run_command("python src/cli.py --help")
    
    # 3. 创建演示文件
    print_header("创建演示文件")
    demo_code = '''
import os
import pickle
import sqlite3

# 漏洞示例
def demo_vulnerabilities():
    # 命令注入
    os.system(input("输入命令: "))
    
    # 反序列化
    pickle.loads(input("序列化数据: "))
    
    # SQL注入
    conn = sqlite3.connect(":memory:")
    conn.execute(f"SELECT * FROM users WHERE id = {input('用户ID: ')}")
    
    # 路径遍历
    open(input("文件名: "), "r")
    
    # 安全示例
    import ast
    ast.literal_eval("[1, 2, 3]")  # 安全
'''
    
    with open("demo_vulnerable.py", "w") as f:
        f.write(demo_code)
    print("✅ 创建演示文件: demo_vulnerable.py")
    
    # 4. 基础扫描
    print_header("基础漏洞扫描（不使用AI）")
    run_command("python src/cli.py scan demo_vulnerable.py")
    
    # 5. AI增强扫描（如果API密钥可用）
    has_api_key = check_api_key()
    
    if has_api_key:
        print_header("AI增强安全扫描")
        success, output = run_command("python src/cli.py scan demo_vulnerable.py --ai --format summary")
        
        if success:
            print_header("生成详细JSON报告")
            run_command("python src/cli.py scan demo_vulnerable.py --ai --format json --output demo_report.json")
            
            # 读取并显示报告摘要
            if os.path.exists("demo_report.json"):
                with open("demo_report.json", "r") as f:
                    report = json.load(f)
                
                print_header("AI扫描报告摘要")
                print(f"📊 项目: {report['project']}")
                print(f"⏰ 扫描时间: {report['scan_time']}")
                stats = report['statistics']
                print(f"🔍 发现API调用: {stats['total_apis']} 个")
                print(f"🔴 高风险: {stats['high_risk']} 个")
                print(f"🟡 中风险: {stats['medium_risk']} 个")
                print(f"🤖 AI深度分析: {stats['ai_analyzed']} 个")
                
                # 显示一个高风险漏洞详情
                print_header("高风险漏洞示例")
                for vuln in report['vulnerabilities']:
                    if vuln.get('risk_level') == 'high':
                        print(f"🔴 漏洞: {vuln['vulnerability']}")
                        print(f"   位置: {vuln.get('file', 'unknown')}:{vuln.get('line', '?')}")
                        print(f"   调用: {vuln['api']}")
                        print(f"   建议: {vuln['suggestion']}")
                        break
    else:
        print_header("⚠️ AI功能说明")
        print("未检测到DeepSeek API密钥，跳过AI扫描演示。")
        print("\n要启用AI功能，请:")
        print("1. 获取DeepSeek API密钥: https://platform.deepseek.com/")
        print("2. 设置环境变量: export DEEPSEEK_API_KEY='your_key'")
        print("3. 或创建.env文件: echo 'DEEPSEEK_API_KEY=your_key' > .env")
        print("\n然后重新运行演示查看AI功能。")
    
    # 6. 扫描示例目录
    print_header("扫描examples目录")
    if os.path.exists("examples"):
        run_command("python src/cli.py scan examples/ --format summary")
    
    # 7. 运行单元测试
    print_header("运行单元测试")
    run_command("python -m pytest tests/unit/ -v", capture=False)
    
    # 8. 清理
    print_header("清理临时文件")
    for f in ["demo_vulnerable.py", "demo_report.json"]:
        if os.path.exists(f):
            os.remove(f)
            print(f"✅ 删除: {f}")
    
    print("\n" + "="*60)
    print("🎉 演示完成！")
    print("="*60)
    print("\n📚 了解更多:")
    print("• 查看文档: https://github.com/yourusername/PySafeScan")
    print("• 报告问题: GitHub Issues")
    print("• 贡献代码: Fork & Pull Request")
    print("\n💡 提示: 使用 --ai 参数启用AI分析，获得更精准的安全建议")

if __name__ == "__main__":
    main()
