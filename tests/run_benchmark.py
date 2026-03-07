#!/usr/bin/env python3
"""OWASP Benchmark测试评估脚本 - 简洁版"""

import os
import sys
import csv
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import logging

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from py_safe_scan.core.pipeline import PySafeScanPipeline
from py_safe_scan.llm.prompts import CWE_DESCRIPTIONS

# 配置日志 - 只显示警告和错误
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class OWASPBenchmarkEvaluator:
    """OWASP Benchmark评估器"""
    
    # 类别到CWE的映射
    CATEGORY_TO_CWE = {
        "cmdi": "CWE-78",      # 命令注入
        "pathtraver": "CWE-22", # 路径遍历
        "xss": "CWE-79",        # 跨站脚本
        "sqli": "CWE-89",       # SQL注入
        "crypto": "CWE-327",    # 加密问题
        "hash": "CWE-328",      # 哈希问题
        "ldapi": "CWE-90",       # LDAP注入
        "securecookie": "CWE-614", # 安全cookie
        "weakrand": "CWE-330",   # 弱随机数
        "trustbound": "CWE-501"  # 信任边界
    }
    
    def __init__(self, test_dir: Path, answer_file: Path, output_dir: Path = None):
        """
        初始化评估器
        
        Args:
            test_dir: 测试用例目录
            answer_file: 答案CSV文件
            output_dir: 输出目录
        """
        self.test_dir = Path(test_dir)
        self.answer_file = Path(answer_file)
        self.output_dir = Path(output_dir) if output_dir else self.test_dir / "results"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 加载答案
        self.expected_results = self._load_answers()
        
        # 测试结果
        self.results = {}
        self.stats = {
            "total_tests": 0,
            "by_category": defaultdict(lambda: {"total": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0}),
            "by_cwe": defaultdict(lambda: {"total": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0})
        }
        
    def _load_answers(self) -> Dict[str, Dict]:
        """
        加载答案CSV文件
        
        Returns:
            {test_name: {"category": str, "vulnerable": bool, "cwe": str}}
        """
        expected = {}
        
        try:
            with open(self.answer_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                
                for row in reader:
                    # 跳过空行和注释
                    if not row or row[0].startswith('#'):
                        continue
                    
                    if len(row) >= 4:
                        test_name = row[0].strip()
                        category = row[1].strip()
                        is_vulnerable = row[2].strip().lower() == 'true'
                        cwe = f"CWE-{row[3].strip()}"
                        
                        expected[test_name] = {
                            "category": category,
                            "vulnerable": is_vulnerable,
                            "cwe": cwe
                        }
                        
            logger.info(f"加载了 {len(expected)} 个测试用例的答案")
            return expected
            
        except Exception as e:
            logger.error(f"加载答案文件失败: {e}")
            return {}
    
    def run_test(self, test_name: str, test_file: Path, cwe: str) -> Dict:
        """
        运行单个测试用例
        
        Args:
            test_name: 测试名称
            test_file: 测试文件路径
            cwe: 要检测的CWE类型
            
        Returns:
            检测结果
        """
        try:
            pipeline = PySafeScanPipeline(
                cwe_type=cwe,
                use_cache=True
            )
            
            results = pipeline.analyze_file(test_file)
            
            # 检查是否检测到漏洞
            vulnerabilities = results.get("vulnerabilities", [])
            detected = len(vulnerabilities) > 0
            
            return {
                "test_name": test_name,
                "file": str(test_file),
                "cwe": cwe,
                "detected": detected,
                "vulnerabilities": vulnerabilities,
                "stats": results.get("stats", {}),
                "success": True
            }
            
        except Exception as e:
            logger.error(f"测试失败 {test_name}: {e}")
            return {
                "test_name": test_name,
                "file": str(test_file),
                "cwe": cwe,
                "detected": False,
                "vulnerabilities": [],
                "error": str(e),
                "success": False
            }
    
    def run_all_tests(self, categories: List[str] = None, limit: int = None):
        """
        运行所有测试用例
        
        Args:
            categories: 要测试的类别列表，None表示全部
            limit: 限制测试数量
        """
        # 收集所有测试文件
        test_files = sorted(self.test_dir.glob("BenchmarkTest*.py"))
        logger.info(f"找到 {len(test_files)} 个测试文件")
        
        if limit:
            test_files = test_files[:limit]
            logger.info(f"限制测试数量为 {limit}")
        
        self.stats["total_tests"] = len(test_files)
        
        # 按类别过滤
        if categories:
            filtered_files = []
            for test_file in test_files:
                test_name = test_file.stem
                if test_name in self.expected_results:
                    category = self.expected_results[test_name]["category"]
                    if category in categories:
                        filtered_files.append(test_file)
            test_files = filtered_files
            logger.info(f"按类别过滤后剩余 {len(test_files)} 个测试文件")
        
        # 运行测试
        start_time = time.time()
        
        print(f"\n{'='*70}")
        print(f"开始测试 {len(test_files)} 个文件")
        print(f"{'='*70}\n")
        
        for i, test_file in enumerate(test_files, 1):
            test_name = test_file.stem
            
            if test_name not in self.expected_results:
                logger.warning(f"测试 {test_name} 没有对应的答案，跳过")
                continue
            
            expected = self.expected_results[test_name]
            category = expected["category"]
            cwe = expected["cwe"]
            is_vulnerable = expected["vulnerable"]
            
            # 显示进度
            print(f"[{i:3d}/{len(test_files)}] {test_name:20} ", end="", flush=True)
            
            # 运行测试
            result = self.run_test(test_name, test_file, cwe)
            self.results[test_name] = result
            
            # 更新统计
            self._update_stats(test_name, expected, result)
            
            # 显示结果
            detected = result.get("detected", False)
            if is_vulnerable and detected:
                print(f"✅ TP (正确检出)")
            elif is_vulnerable and not detected:
                print(f"❌ FN (漏报)")
            elif not is_vulnerable and detected:
                print(f"⚠️ FP (误报)")
            else:
                print(f"✓ TN (正确排除)")
            
            # 进度时间估计
            elapsed = time.time() - start_time
            avg_time = elapsed / i
            remaining = avg_time * (len(test_files) - i)
            
            if i % 10 == 0:
                print(f"    进度: {i}/{len(test_files)}, 预计剩余: {remaining/60:.1f}分钟")
        
        # 生成报告
        self._generate_report()
    
    def _update_stats(self, test_name: str, expected: Dict, result: Dict):
        """更新统计信息"""
        category = expected["category"]
        cwe = expected["cwe"]
        is_vulnerable = expected["vulnerable"]
        detected = result.get("detected", False)
        
        # 更新总数
        self.stats["by_category"][category]["total"] += 1
        self.stats["by_cwe"][cwe]["total"] += 1
        
        # 更新TP/FP/TN/FN
        if is_vulnerable and detected:
            self.stats["by_category"][category]["tp"] += 1
            self.stats["by_cwe"][cwe]["tp"] += 1
        elif is_vulnerable and not detected:
            self.stats["by_category"][category]["fn"] += 1
            self.stats["by_cwe"][cwe]["fn"] += 1
        elif not is_vulnerable and detected:
            self.stats["by_category"][category]["fp"] += 1
            self.stats["by_cwe"][cwe]["fp"] += 1
        elif not is_vulnerable and not detected:
            self.stats["by_category"][category]["tn"] += 1
            self.stats["by_cwe"][cwe]["tn"] += 1
    
    def _generate_report(self):
        """生成评估报告"""
        report = {
            "summary": self._calculate_summary(),
            "by_category": {},
            "by_cwe": {},
            "detailed_results": self.results,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # 按类别统计
        for category, stats in self.stats["by_category"].items():
            report["by_category"][category] = self._calculate_metrics(stats)
        
        # 按CWE统计
        for cwe, stats in self.stats["by_cwe"].items():
            report["by_cwe"][cwe] = self._calculate_metrics(stats)
        
        # 保存报告
        report_file = self.output_dir / "benchmark_report.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # 生成CSV报告
        self._generate_csv_report()
        
        # 打印结果
        self._print_summary(report)
        
        logger.info(f"报告已保存到: {report_file}")
    
    def _calculate_summary(self) -> Dict:
        """计算总体统计"""
        total_tp = sum(s["tp"] for s in self.stats["by_category"].values())
        total_fp = sum(s["fp"] for s in self.stats["by_category"].values())
        total_tn = sum(s["tn"] for s in self.stats["by_category"].values())
        total_fn = sum(s["fn"] for s in self.stats["by_category"].values())
        
        return self._calculate_metrics({
            "tp": total_tp,
            "fp": total_fp,
            "tn": total_tn,
            "fn": total_fn,
            "total": total_tp + total_fp + total_tn + total_fn
        })
    
    def _calculate_metrics(self, stats: Dict) -> Dict:
        """计算各项指标"""
        tp = stats.get("tp", 0)
        fp = stats.get("fp", 0)
        tn = stats.get("tn", 0)
        fn = stats.get("fn", 0)
        total = stats.get("total", tp + fp + tn + fn)
        
        # 计算指标
        tpr = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0  # 召回率/检出率
        fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0  # 误报率
        precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0  # 精确率
        f1 = 2 * (precision * tpr) / (precision + tpr) / 100 if (precision + tpr) > 0 else 0  # F1分数
        accuracy = (tp + tn) / total * 100 if total > 0 else 0  # 准确率
        
        return {
            "total": total,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "tpr": round(tpr, 2),
            "fpr": round(fpr, 2),
            "precision": round(precision, 2),
            "recall": round(tpr, 2),
            "f1": round(f1, 3),
            "accuracy": round(accuracy, 2)
        }
    
    def _generate_csv_report(self):
        """生成CSV格式报告"""
        csv_file = self.output_dir / "benchmark_results.csv"
        
        with open(csv_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            
            # 写入标题
            writer.writerow([
                "Test Name", "Category", "CWE", 
                "Expected", "Detected", "Result"
            ])
            
            for test_name, expected in self.expected_results.items():
                if test_name in self.results:
                    result = self.results[test_name]
                    detected = result.get("detected", False)
                    is_vulnerable = expected["vulnerable"]
                    
                    # 确定结果类型
                    if is_vulnerable and detected:
                        result_type = "TP"
                    elif is_vulnerable and not detected:
                        result_type = "FN"
                    elif not is_vulnerable and detected:
                        result_type = "FP"
                    else:
                        result_type = "TN"
                    
                    writer.writerow([
                        test_name,
                        expected["category"],
                        expected["cwe"],
                        "true" if is_vulnerable else "false",
                        "true" if detected else "false",
                        result_type
                    ])
    
    def _print_summary(self, report: Dict):
        """打印简洁的总结"""
        print("\n" + "="*70)
        print("📊 OWASP Benchmark 评估结果")
        print("="*70)
        
        # 总体结果
        summary = report["summary"]
        print(f"\n📈 总体统计:")
        print(f"  总测试数: {summary['total']}")
        print(f"  真阳性(TP): {summary['tp']}")
        print(f"  假阳性(FP): {summary['fp']}")
        print(f"  真阴性(TN): {summary['tn']}")
        print(f"  假阴性(FN): {summary['fn']}")
        print(f"\n  检出率(TPR): {summary['tpr']}%")
        print(f"  误报率(FPR): {summary['fpr']}%")
        print(f"  精确率: {summary['precision']}%")
        print(f"  F1分数: {summary['f1']}")
        print(f"  准确率: {summary['accuracy']}%")
        
        # 按CWE分类（简洁版）
        print("\n📊 按CWE分类:")
        for cwe, metrics in report["by_cwe"].items():
            print(f"  {cwe}: TP={metrics['tp']}, FP={metrics['fp']}, "
                  f"检出率={metrics['tpr']}%, 误报率={metrics['fpr']}%")


def main():
    parser = argparse.ArgumentParser(description="OWASP Benchmark评估工具")
    parser.add_argument("--test-dir", type=str, 
                       default="/home/hanahanarange/PySafeScan/tests/BenchmarkPython/testcode",
                       help="测试用例目录")
    parser.add_argument("--answer-file", type=str,
                       default="/home/hanahanarange/PySafeScan/tests/BenchmarkPython/expectedresults-0.1.csv",
                       help="答案文件路径")
    parser.add_argument("--output-dir", type=str,
                       default="/home/hanahanarange/PySafeScan/tests/BenchmarkPython/results",
                       help="输出目录")
    parser.add_argument("--categories", type=str, nargs="+",
                       choices=["cmdi", "pathtraver", "xss", "sqli", "crypto", 
                               "hash", "ldapi", "securecookie", "weakrand", "trustbound"],
                       help="要测试的类别")
    parser.add_argument("--limit", type=int, default=20,
                       help="限制测试数量")
    parser.add_argument("--cwe", type=str,
                       choices=["CWE-22", "CWE-78", "CWE-79", "CWE-89"],
                       help="只测试特定CWE")
    
    args = parser.parse_args()
    
    # 创建评估器
    evaluator = OWASPBenchmarkEvaluator(
        test_dir=Path(args.test_dir),
        answer_file=Path(args.answer_file),
        output_dir=Path(args.output_dir) if args.output_dir else None
    )
    
    # 如果指定了CWE，转换为对应的category
    categories = args.categories
    if args.cwe:
        cwe_to_category = {v: k for k, v in OWASPBenchmarkEvaluator.CATEGORY_TO_CWE.items()}
        if args.cwe in cwe_to_category:
            categories = [cwe_to_category[args.cwe]]
            print(f"转换为类别: {categories}")
    
    # 运行测试
    evaluator.run_all_tests(categories=categories, limit=args.limit)


if __name__ == "__main__":
    main()
