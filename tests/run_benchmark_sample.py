#!/usr/bin/env python3
"""基准测试样本 - 只测试前20个文件"""

import sys
import csv
import json
import time
from pathlib import Path
from typing import Dict, List

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from py_safe_scan.core.pipeline import IRISPipeline

# 配置
TEST_DIR = "/home/hanahanarange/PySafeScan/tests/BenchmarkPython/testcode"
ANSWER_FILE = "/home/hanahanarange/PySafeScan/tests/BenchmarkPython/expectedresults-0.1.csv"

def load_answers(limit=20):
    """加载答案CSV文件，只取前limit个"""
    answers = {}
    
    with open(ANSWER_FILE, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        count = 0
        for row in reader:
            if not row or row[0].startswith('#'):
                continue
            if len(row) >= 4 and count < limit:
                test_name = row[0].strip()
                category = row[1].strip()
                is_vulnerable = row[2].strip().lower() == 'true'
                cwe = f"CWE-{row[3].strip()}"
                
                answers[test_name] = {
                    "category": category,
                    "vulnerable": is_vulnerable,
                    "cwe": cwe
                }
                count += 1
    
    print(f"加载了 {len(answers)} 个测试用例的答案")
    return answers

def analyze_single_file(test_name: str, file_path: Path, cwe: str) -> Dict:
    """分析单个文件"""
    print(f"\n测试: {test_name} ({cwe})")
    print("-" * 50)
    
    try:
        # 为每个测试文件创建独立的临时工作目录
        import tempfile
        import shutil
        from pathlib import Path
        
        # 创建临时工作目录
        temp_workspace = Path(tempfile.mkdtemp(prefix=f"codeql_{test_name}_"))
        
        # 修改配置，使用临时工作目录
        import config
        original_workspace = config.CODEQL_WORKSPACE
        config.CODEQL_WORKSPACE = temp_workspace
        
        # 创建pipeline实例
        pipeline = IRISPipeline(cwe_type=cwe, use_cache=False)
        
        # 分析文件
        results = pipeline.analyze_file(file_path)
        
        # 恢复原始配置
        config.CODEQL_WORKSPACE = original_workspace
        
        # 清理临时目录
        shutil.rmtree(temp_workspace, ignore_errors=True)
        
        vulnerabilities = results.get("vulnerabilities", [])
        detected = len(vulnerabilities) > 0
        
        print(f"  检测到漏洞: {detected}")
        if detected:
            print(f"  漏洞数: {len(vulnerabilities)}")
            for i, v in enumerate(vulnerabilities[:2]):
                print(f"    {i+1}. {v.get('file')}:{v.get('line')} - {v.get('cwe')}")
        
        return {
            "test_name": test_name,
            "cwe": cwe,
            "detected": detected,
            "vulnerabilities": len(vulnerabilities),
            "success": True
        }
        
    except Exception as e:
        print(f"  错误: {e}")
        import traceback
        traceback.print_exc()
        return {
            "test_name": test_name,
            "cwe": cwe,
            "detected": False,
            "vulnerabilities": 0,
            "success": False,
            "error": str(e)
        }

def main():
    """主函数"""
    print("="*70)
    print("基准测试样本 - 前20个文件")
    print("="*70)
    
    # 加载答案
    answers = load_answers(20)
    
    results = []
    tp = fp = tn = fn = 0
    
    for i, (test_name, info) in enumerate(answers.items(), 1):
        file_path = Path(TEST_DIR) / f"{test_name}.py"
        
        if not file_path.exists():
            print(f"文件不存在: {file_path}")
            continue
        
        print(f"\n[{i}/20] ", end="")
        result = analyze_single_file(test_name, file_path, info["cwe"])
        results.append(result)
        
        # 更新统计
        expected = info["vulnerable"]
        detected = result["detected"]
        
        if expected and detected:
            tp += 1
            status = "✅ TP"
        elif expected and not detected:
            fn += 1
            status = "❌ FN"
        elif not expected and detected:
            fp += 1
            status = "⚠️ FP"
        else:
            tn += 1
            status = "✓ TN"
        
        print(f"  预期: {expected}, 实际: {detected} -> {status}")
    
    # 打印汇总
    print("\n" + "="*70)
    print("📊 测试结果汇总")
    print("="*70)
    print(f"总测试数: {len(results)}")
    print(f"真阳性(TP): {tp}")
    print(f"假阳性(FP): {fp}")
    print(f"真阴性(TN): {tn}")
    print(f"假阴性(FN): {fn}")
    
    if tp + fn > 0:
        recall = tp / (tp + fn) * 100
        print(f"召回率: {recall:.1f}%")
    
    if tp + fp > 0:
        precision = tp / (tp + fp) * 100
        print(f"精确率: {precision:.1f}%")
    
    # 保存结果
    output_file = Path("benchmark_sample_results.json")
    with open(output_file, 'w') as f:
        json.dump({
            "results": results,
            "summary": {
                "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                "total": len(results)
            }
        }, f, indent=2)
    print(f"\n结果已保存: {output_file}")

if __name__ == "__main__":
    main()
