# tests/test_iris_full.py
"""完整测试IRIS四阶段实现"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))

from py_safe_scan.core.pipeline import IRISPipeline
from py_safe_scan.llm.prompts import CWE_DESCRIPTIONS


def create_test_project() -> Path:
    """创建一个包含多种漏洞的测试项目"""
    test_dir = Path("iris_test_project")
    test_dir.mkdir(exist_ok=True)
    
    # 1. SQL注入漏洞
    sqli_file = test_dir / "app_sqli.py"
    sqli_file.write_text("""
import sqlite3
from flask import request

def get_user():
    # SQL注入漏洞：直接拼接用户输入
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 漏洞点
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    
    # 安全版本（用于对比）
    safe_query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(safe_query, (user_id,))
    
    return cursor.fetchall()

@app.route('/user')
def user_profile():
    data = get_user()
    return {'users': data}
""")
    
    # 2. 命令注入漏洞
    cmdi_file = test_dir / "utils_cmdi.py"
    cmdi_file.write_text("""
import os
import subprocess
from flask import request

def ping_host():
    # 命令注入漏洞
    host = request.args.get('host')
    
    # 漏洞点
    os.system("ping -c 4 " + host)
    
    # 另一个漏洞点
    subprocess.run("ping " + host, shell=True)
    
    # 安全版本
    subprocess.run(["ping", "-c", "4", host])
    
@app.route('/ping')
def ping():
    ping_host()
    return 'Ping executed'
""")
    
    # 3. 路径遍历漏洞
    path_file = test_dir / "file_handler.py"
    path_file.write_text("""
import os
from flask import request, send_file

def read_file():
    # 路径遍历漏洞
    filename = request.args.get('file')
    
    # 漏洞点
    with open("/app/files/" + filename, 'r') as f:
        return f.read()

@app.route('/download')
def download():
    filename = request.args.get('file')
    # 漏洞点
    return send_file("/app/files/" + filename)
""")
    
    # 4. XSS漏洞
    xss_file = test_dir / "views.py"
    xss_file.write_text("""
from flask import request, render_template_string

@app.route('/profile')
def profile():
    # XSS漏洞
    name = request.args.get('name')
    
    # 漏洞点
    return render_template_string("<h1>Hello " + name + "</h1>")

@app.route('/search')
def search():
    query = request.args.get('q')
    # 另一个漏洞点
    return f"<div>Search results for: {query}</div>"
""")
    
    # 5. XXE漏洞
    xxe_file = test_dir / "xml_parser.py"
    xxe_file.write_text("""
from flask import request
import xml.etree.ElementTree as ET
import lxml.etree

@app.route('/parse_xml')
def parse_xml():
    # XXE漏洞
    xml_data = request.data
    
    # 漏洞点
    root = ET.fromstring(xml_data)
    
    # 另一个漏洞点
    root2 = lxml.etree.fromstring(xml_data)
    
    return 'XML parsed'
""")
    
    # 6. 公开函数参数（用于测试函数参数推断）
    api_file = test_dir / "api.py"
    api_file.write_text("""
\"\"\"
这个模块提供了用户管理的API函数
这些函数会被其他模块调用，参数可能来自用户输入
\"\"\"

def get_user_profile(user_id: str, include_private: bool = False):
    \"\"\"
    获取用户配置信息
    
    Args:
        user_id: 用户ID，来自请求参数
        include_private: 是否包含私有信息
    
    Returns:
        用户配置字典
    \"\"\"
    # 这个函数的参数可能被污染
    return {"id": user_id, "name": "test"}

def update_user_settings(user_id: str, settings: dict):
    \"\"\"
    更新用户设置
    
    Args:
        user_id: 用户ID
        settings: 用户设置，可能来自请求体
    \"\"\"
    # 危险操作
    exec(f"update user {user_id} set {settings}")

@app.route('/api/user/<user_id>')
def user_api(user_id):
    # 用户输入直接传递给公开函数
    return get_user_profile(user_id)
""")
    
    print(f"测试项目创建完成: {test_dir}")
    print("包含的漏洞文件:")
    for f in test_dir.glob("*.py"):
        print(f"  - {f.name}")
    
    return test_dir


def test_iris_pipeline():
    """测试IRIS完整流水线"""
    
    print("\n" + "="*70)
    print("🚀 测试IRIS完整流水线")
    print("="*70)
    
    # 创建测试项目
    test_dir = create_test_project()
    
    # 测试不同的CWE类型
    cwes_to_test = ["CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-611"]
    
    all_results = {}
    
    for cwe in cwes_to_test:
        print(f"\n{'='*70}")
        print(f"测试 {cwe}: {CWE_DESCRIPTIONS.get(cwe, '')}")
        print(f"{'='*70}")
        
        # 初始化流水线
        pipeline = IRISPipeline(cwe_type=cwe, use_cache=True)
        
        # 执行分析
        start = time.time()
        results = pipeline.analyze_directory(test_dir)
        elapsed = time.time() - start
        
        # 保存结果
        all_results[cwe] = {
            "raw_count": results["stats"]["vulnerabilities_found"],
            "confirmed_count": results["stats"]["vulnerabilities_confirmed"],
            "llm_calls": results["stats"]["llm_calls"],
            "external_apis": results["stats"]["external_apis_found"],
            "time": elapsed
        }
        
        # 打印漏洞详情
        print(f"\n📋 漏洞详情:")
        for i, vuln in enumerate(results["vulnerabilities"][:3], 1):
            print(f"\n  {i}. {vuln.get('file')}:{vuln.get('line')}")
            print(f"     类型: {vuln.get('cwe')}")
            if vuln.get('explanation'):
                print(f"     解释: {vuln.get('explanation')[:100]}...")
            if vuln.get('recommendation'):
                print(f"     修复: {vuln.get('recommendation')[:100]}...")
    
    # 打印汇总
    print("\n" + "="*70)
    print("📊 IRIS测试汇总")
    print("="*70)
    
    total_raw = 0
    total_confirmed = 0
    total_llm = 0
    
    for cwe, res in all_results.items():
        print(f"\n{cwe}:")
        print(f"  外部API: {res['external_apis']}个")
        print(f"  原始漏洞: {res['raw_count']}个")
        print(f"  确认漏洞: {res['confirmed_count']}个")
        print(f"  LLM调用: {res['llm_calls']}次")
        print(f"  耗时: {res['time']:.2f}秒")
        
        if res['raw_count'] > 0:
            filter_rate = (1 - res['confirmed_count']/res['raw_count']) * 100
            print(f"  过滤率: {filter_rate:.1f}%")
        
        total_raw += res['raw_count']
        total_confirmed += res['confirmed_count']
        total_llm += res['llm_calls']
    
    print(f"\n总计:")
    print(f"  原始漏洞总数: {total_raw}")
    print(f"  确认漏洞总数: {total_confirmed}")
    print(f"  总LLM调用: {total_llm}")
    
    if total_raw > 0:
        overall_filter = (1 - total_confirmed/total_raw) * 100
        print(f"  总体过滤率: {overall_filter:.1f}%")
    
    # 保存完整结果
    result_file = test_dir / "iris_test_results.json"
    with open(result_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n结果已保存: {result_file}")


def test_spec_inference():
    """单独测试规范推断功能"""
    
    print("\n" + "="*70)
    print("🔍 测试规范推断")
    print("="*70)
    
    from py_safe_scan.core.pipeline import IRISPipeline
    from py_safe_scan.core.spec_extractor import ExternalAPI
    
    pipeline = IRISPipeline(cwe_type="CWE-89", use_cache=True)
    
    # 模拟外部API列表 - 注意这里去掉了signature参数
    test_apis = [
        ExternalAPI(
            package="flask",
            class_name="request",
            method="args.get",
            file="app.py",
            line=10,
            context="request.args.get('id')"
        ),
        ExternalAPI(
            package="flask",
            class_name="request",
            method="form.get",
            file="app.py",
            line=15,
            context="request.form.get('name')"
        ),
        ExternalAPI(
            package="sqlite3",
            class_name="Cursor",
            method="execute",
            file="db.py",
            line=20,
            context="cursor.execute(query)"
        ),
        ExternalAPI(
            package="os",
            class_name=None,
            method="system",
            file="utils.py",
            line=25,
            context="os.system(cmd)"
        )
    ]
    
    # 转换为字典格式
    api_dicts = []
    for api in test_apis:
        api_dicts.append({
            "package": api.package,
            "class": api.class_name,
            "method": api.method,
            "file": api.file,
            "line": api.line
        })
    
    # 获取CWE描述和few-shot示例
    cwe_desc = CWE_DESCRIPTIONS.get("CWE-89", "")
    few_shot = FEW_SHOT_EXAMPLES.get("CWE-89", [])
    
    # 调用LLM推断
    print("\n调用DeepSeek API进行规范推断...")
    inferred_apis = pipeline.deepseek.infer_source_sink_specs(
        apis=api_dicts,
        cwe_type="CWE-89",
        cwe_description=cwe_desc,
        few_shot_examples=few_shot
    )
    
    print("\n推断结果:")
    print(f"  总API数: {len(inferred_apis)}")
    
    sources = [a for a in inferred_apis if a.get("llm_label") == "source"]
    sinks = [a for a in inferred_apis if a.get("llm_label") == "sink"]
    
    print(f"  Sources: {len(sources)}个")
    for s in sources:
        print(f"    - {s.get('package')}.{s.get('method')} (置信度: {s.get('llm_confidence')}%)")
        print(f"      解释: {s.get('explanation', '')}")
    
    print(f"\n  Sinks: {len(sinks)}个")
    for s in sinks:
        print(f"    - {s.get('package')}.{s.get('method')} (置信度: {s.get('llm_confidence')}%)")
        print(f"      解释: {s.get('explanation', '')}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="测试IRIS完整实现")
    parser.add_argument("--test", choices=["all", "pipeline", "spec"], default="all")
    
    args = parser.parse_args()
    
    if args.test == "all" or args.test == "pipeline":
        test_iris_pipeline()
    
    if args.test == "all" or args.test == "spec":
        test_spec_inference()
