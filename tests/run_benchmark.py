#!/usr/bin/env python3
"""OWASP Benchmark测试评估脚本 - 增强版（支持多轮推理评估）"""

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
    """OWASP Benchmark评估器 - 增强版"""
    
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
        "trustbound": "CWE-501",  # 信任边界
        "xpathi": "CWE-643",      # XPath注入
        "xxe": "CWE-611",         # XXE
        "codeinj": "CWE-94",      # 代码注入
        "deserialization": "CWE-502", # 反序列化
        "redirect": "CWE-601",    # URL重定向
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
        
        # 详细统计（用于分析改进效果）
        self.detailed_stats = {
            "llm_calls": 0,
            "cache_hits": 0,
            "source_candidates": 0,
            "sink_candidates": 0,
            "filtering_stats": {
                "before_filter": 0,
                "after_filter": 0,
                "after_validation": 0
            },
            "time_stats": {
                "total_time": 0,
                "avg_time_per_file": 0
            }
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
                        cwe_num = row[3].strip()
                        
                        # 处理CWE格式
                        if cwe_num.isdigit():
                            cwe = f"CWE-{cwe_num}"
                        else:
                            cwe = cwe_num
                        
                        expected[test_name] = {
                            "category": category,
                            "vulnerable": is_vulnerable,
                            "cwe": cwe
                        }
                        
            logger.info(f"加载了 {len(expected)} 个测试用例的答案")
            print(f"📊 加载了 {len(expected)} 个测试用例")
            
            # 按CWE统计
            cwe_counts = defaultdict(int)
            for _, info in expected.items():
                cwe_counts[info['cwe']] += 1
            
            print(f"  分布: {dict(cwe_counts)}")
            
            return expected
            
        except Exception as e:
            logger.error(f"加载答案文件失败: {e}")
            return {}
    
    def run_test(self, test_name: str, test_file: Path, cwe: str) -> Dict:
        """
        运行单个测试用例 - 单次运行
        """
        try:
            pipeline = PySafeScanPipeline(
                cwe_type=cwe,
                use_cache=True
            )
            
            start_time = time.time()
            results = pipeline.analyze_file(test_file)
            elapsed = time.time() - start_time
            
            vulnerabilities = results.get("vulnerabilities", [])
            detected = len(vulnerabilities) > 0
            
            return {
                "test_name": test_name,
                "file": str(test_file),
                "cwe": cwe,
                "detected": detected,
                "vulnerabilities": vulnerabilities,
                "raw_count": results.get("stats", {}).get("vulnerabilities_found", 0),
                "filtered_count": results.get("stats", {}).get("vulnerabilities_filtered", 0),
                "confirmed_count": results.get("stats", {}).get("vulnerabilities_confirmed", 0),
                "llm_calls": results.get("stats", {}).get("llm_calls", 0),
                "cache_hits": results.get("stats", {}).get("cache_hits", 0),
                "source_candidates": results.get("stats", {}).get("source_candidates", 0),
                "sink_candidates": results.get("stats", {}).get("sink_candidates", 0),
                "time_elapsed": elapsed,
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
                "raw_count": 0,
                "filtered_count": 0,
                "confirmed_count": 0,
                "llm_calls": 0,
                "cache_hits": 0,
                "source_candidates": 0,
                "sink_candidates": 0,
                "time_elapsed": 0,
                "error": str(e),
                "success": False
            }
    
    def run_all_tests(self, categories: List[str] = None, limit: int = None):
        """
        运行所有测试用例 - 增强版进度显示和统计
        
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
        print(f"🚀 开始测试 {len(test_files)} 个文件")
        print(f"{'='*70}\n")
        
        # 统计累加器
        total_llm_calls = 0
        total_cache_hits = 0
        total_raw = 0
        total_filtered = 0
        total_confirmed = 0
        
        for i, test_file in enumerate(test_files, 1):
            test_name = test_file.stem
            
            if test_name not in self.expected_results:
                logger.warning(f"测试 {test_name} 没有对应的答案，跳过")
                continue
            
            expected = self.expected_results[test_name]
            category = expected["category"]
            cwe = expected["cwe"]
            is_vulnerable = expected["vulnerable"]
            
            # ============ 只运行有漏洞的 ============
#            if not is_vulnerable:
 #               print(f"[{i:3d}/{len(test_files)}] {test_name:20} ⏭️ 跳过 (无漏洞)")
  #              continue
            
            # ============ 跳过不支持的CWE ============
            unsupported_cwes = ["CWE-328", "CWE-330", "CWE-501", "CWE-798"]
            if cwe in unsupported_cwes:
                print(f"[{i:3d}/{len(test_files)}] {test_name:20} ⏭️ 跳过 (CWE不支持)")
                continue
            # =========================================
            
            # 显示进度
            print(f"[{i:3d}/{len(test_files)}] {test_name:20} ", end="", flush=True)
            
            # 运行测试
            result = self.run_test(test_name, test_file, cwe)
            self.results[test_name] = result
            
            # 更新统计
            self._update_stats(test_name, expected, result)
            
            # 累加详细统计
            if result.get("success", False):
                total_llm_calls += result.get("llm_calls", 0)
                total_cache_hits += result.get("cache_hits", 0)
                total_raw += result.get("raw_count", 0)
                total_filtered += result.get("filtered_count", 0)
                total_confirmed += result.get("confirmed_count", 0)
            
            # 显示结果
            detected = result.get("detected", False)
            raw = result.get("raw_count", 0)
            filtered = result.get("filtered_count", 0)
            confirmed = result.get("confirmed_count", 0)
            
            if is_vulnerable and detected:
                status = f"✅ TP (正确检出) [{raw}→{filtered}→{confirmed}]"
            elif is_vulnerable and not detected:
                status = f"❌ FN (漏报) [{raw}→{filtered}→{confirmed}]"
            elif not is_vulnerable and detected:
                status = f"⚠️ FP (误报) [{raw}→{filtered}→{confirmed}]"
            else:
                status = f"✓ TN (正确排除) [{raw}→{filtered}→{confirmed}]"
            
            print(status)
            
            # 每10个文件显示一次进度统计
            if i % 10 == 0:
                elapsed = time.time() - start_time
                avg_time = elapsed / i
                remaining = avg_time * (len(test_files) - i)
                
                # 计算当前准确率
                current_tp = self.stats["by_cwe"][cwe]["tp"]
                current_fp = self.stats["by_cwe"][cwe]["fp"]
                current_fn = self.stats["by_cwe"][cwe]["fn"]
                current_tn = self.stats["by_cwe"][cwe]["tn"]
                
                precision = current_tp / (current_tp + current_fp) * 100 if (current_tp + current_fp) > 0 else 0
                recall = current_tp / (current_tp + current_fn) * 100 if (current_tp + current_fn) > 0 else 0
                
                print(f"    进度: {i}/{len(test_files)}, 剩余: {remaining/60:.1f}分钟")
                print(f"    当前: TP={current_tp}, FP={current_fp}, 精确率={precision:.1f}%, 召回率={recall:.1f}%")
        
        # 更新详细统计
        elapsed_total = time.time() - start_time
        self.detailed_stats["llm_calls"] = total_llm_calls
        self.detailed_stats["cache_hits"] = total_cache_hits
        self.detailed_stats["filtering_stats"]["before_filter"] = total_raw
        self.detailed_stats["filtering_stats"]["after_filter"] = total_filtered
        self.detailed_stats["filtering_stats"]["after_validation"] = total_confirmed
        self.detailed_stats["time_stats"]["total_time"] = elapsed_total
        self.detailed_stats["time_stats"]["avg_time_per_file"] = elapsed_total / len(test_files) if test_files else 0
        
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
        """生成增强版评估报告"""
        report = {
            "summary": self._calculate_summary(),
            "by_category": {},
            "by_cwe": {},
            "detailed_stats": self.detailed_stats,
            "filtering_effectiveness": self._calculate_filtering_effectiveness(),
            "detailed_results": self.results,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # 按类别统计
        for category, stats in self.stats["by_category"].items():
            report["by_category"][category] = self._calculate_metrics(stats)
        
        # 按CWE统计
        for cwe, stats in self.stats["by_cwe"].items():
            report["by_cwe"][cwe] = self._calculate_metrics(stats)
        
        # 保存JSON报告
        report_file = self.output_dir / "benchmark_report_enhanced.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # 生成CSV报告
        self._generate_csv_report()
        
        # 生成过滤效果报告
        self._generate_filtering_report()
        
        # 打印结果
        self._print_enhanced_summary(report)
        
        logger.info(f"增强版报告已保存到: {report_file}")
    
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
    
    def _calculate_filtering_effectiveness(self) -> Dict:
        """计算过滤效果"""
        before = self.detailed_stats["filtering_stats"]["before_filter"]
        after_filter = self.detailed_stats["filtering_stats"]["after_filter"]
        after_validation = self.detailed_stats["filtering_stats"]["after_validation"]
        
        return {
            "原始漏洞数": before,
            "规范过滤后": after_filter,
            "验证通过后": after_validation,
            "规范过滤率": f"{(1 - after_filter/before)*100:.1f}%" if before > 0 else "0%",
            "总过滤率": f"{(1 - after_validation/before)*100:.1f}%" if before > 0 else "0%",
            "平均LLM调用/文件": self.detailed_stats["llm_calls"] / self.stats["total_tests"] if self.stats["total_tests"] > 0 else 0,
            "缓存命中率": f"{self.detailed_stats['cache_hits'] / self.detailed_stats['llm_calls'] * 100:.1f}%" if self.detailed_stats['llm_calls'] > 0 else "0%"
        }
    
    def _generate_csv_report(self):
        """生成CSV格式报告"""
        csv_file = self.output_dir / "benchmark_results_enhanced.csv"
        
        with open(csv_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            
            # 写入标题
            writer.writerow([
                "Test Name", "Category", "CWE", 
                "Expected", "Detected", "Result",
                "Raw Count", "Filtered Count", "Confirmed Count",
                "LLM Calls", "Time(ms)"
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
                        result_type,
                        result.get("raw_count", 0),
                        result.get("filtered_count", 0),
                        result.get("confirmed_count", 0),
                        result.get("llm_calls", 0),
                        round(result.get("time_elapsed", 0) * 1000, 2)
                    ])
    
    def _generate_filtering_report(self):
        """生成过滤效果报告"""
        filter_file = self.output_dir / "filtering_effectiveness.txt"
        
        with open(filter_file, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("IRIS 过滤效果分析\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"总测试文件: {self.stats['total_tests']}\n")
            f.write(f"总LLM调用: {self.detailed_stats['llm_calls']}\n")
            f.write(f"平均LLM调用/文件: {self.detailed_stats['llm_calls'] / self.stats['total_tests']:.2f}\n\n")
            
            f.write("过滤阶段统计:\n")
            f.write(f"  原始漏洞总数: {self.detailed_stats['filtering_stats']['before_filter']}\n")
            f.write(f"  规范过滤后: {self.detailed_stats['filtering_stats']['after_filter']}\n")
            f.write(f"  验证通过后: {self.detailed_stats['filtering_stats']['after_validation']}\n\n")
            
            f.write("过滤率:\n")
            before = self.detailed_stats['filtering_stats']['before_filter']
            if before > 0:
                filter_rate = (1 - self.detailed_stats['filtering_stats']['after_filter'] / before) * 100
                validation_rate = (1 - self.detailed_stats['filtering_stats']['after_validation'] / before) * 100
                f.write(f"  规范过滤阶段: {filter_rate:.1f}%\n")
                f.write(f"  路径验证阶段: {validation_rate - filter_rate:.1f}%\n")
                f.write(f"  总过滤率: {validation_rate:.1f}%\n")
    
    def _print_enhanced_summary(self, report: Dict):
        """打印增强版总结"""
        print("\n" + "="*70)
        print("📊 OWASP Benchmark 评估结果 - 增强版")
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
        
        # 过滤效果
        filtering = report["filtering_effectiveness"]
        print(f"\n🔍 过滤效果:")
        print(f"  原始漏洞数: {filtering['原始漏洞数']}")
        print(f"  规范过滤后: {filtering['规范过滤后']}")
        print(f"  验证通过后: {filtering['验证通过后']}")
        print(f"  总过滤率: {filtering['总过滤率']}")
        print(f"  平均LLM调用/文件: {filtering['平均LLM调用/文件']:.2f}")
        
        # 按CWE分类（只显示支持的）
        print("\n📊 按CWE分类:")
        supported_cwes = ["CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-90", 
                         "CWE-94", "CWE-502", "CWE-601", "CWE-611", "CWE-643"]
        
        for cwe, metrics in report["by_cwe"].items():
            if cwe in supported_cwes:
                cwe_name = cwe
                if cwe in CWE_DESCRIPTIONS:
                    cwe_name = f"{cwe} ({CWE_DESCRIPTIONS[cwe][:30]}...)"
                print(f"\n  {cwe_name}:")
                print(f"    TP={metrics['tp']}, FP={metrics['fp']}, "
                      f"FN={metrics['fn']}, TN={metrics['tn']}")
                print(f"    检出率={metrics['tpr']}%, 误报率={metrics['fpr']}%, "
                      f"精确率={metrics['precision']}%")
        
        print("\n" + "="*70)


def main():
    parser = argparse.ArgumentParser(description="OWASP Benchmark评估工具 - 增强版")
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
                               "hash", "ldapi", "securecookie", "weakrand", "trustbound",
                               "xpathi", "xxe", "codeinj", "deserialization", "redirect"],
                       help="要测试的类别")
    parser.add_argument("--limit", type=int, default=None,
                       help="限制测试数量")
    parser.add_argument("--cwe", type=str,
                       choices=["CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94",
                               "CWE-502", "CWE-601", "CWE-611", "CWE-643"],
                       help="只测试特定CWE")
    parser.add_argument("--compare", action="store_true",
                       help="与原版本比较")
    parser.add_argument("--verbose", action="store_true",
                       help="显示详细信息")
    
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
        # 反向映射
        cwe_to_category = {}
        for cat, cwe in OWASPBenchmarkEvaluator.CATEGORY_TO_CWE.items():
            if cwe == args.cwe:
                cwe_to_category[cwe] = cat
        
        if args.cwe in cwe_to_category:
            categories = [cwe_to_category[args.cwe]]
            print(f"🔍 只测试CWE {args.cwe} -> 类别: {categories}")
        else:
            print(f"⚠️ CWE {args.cwe} 没有对应的类别，将测试所有")
    
    # 运行测试
    evaluator.run_all_tests(categories=categories, limit=args.limit)
    
    # 如果需要与原版本比较，可以在这里添加


if __name__ == "__main__":
    main()
