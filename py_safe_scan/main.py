"""PySafeScan主入口"""

import argparse
import logging
import sys
import json
import time
from pathlib import Path
from typing import List, Optional, Dict

from py_safe_scan.core.pipeline import PySafeScanPipeline
from py_safe_scan.utils.sarif_generator import SARIFGenerator
from py_safe_scan.llm.prompts import CWE_DESCRIPTIONS
import config

# 配置日志
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="PySafeScan - LLM赋能Python漏洞检测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
支持的CWE类型:
  {', '.join(config.SUPPORTED_CWES)}

示例:
  # 分析单个文件
  python -m py_safe_scan.main --target app.py --cwe CWE-89

  # 分析整个项目
  python -m py_safe_scan.main --target ./my_project --cwe CWE-89 --recursive

  # 生成SARIF报告
  python -m py_safe_scan.main --target app.py --cwe CWE-89 --output report.sarif

  # 显示详细漏洞路径
  python -m py_safe_scan.main --target app.py --cwe CWE-89 --verbose
        """
    )
    
    parser.add_argument(
        "--target", 
        type=str, 
        required=True,
        help="目标文件或目录路径"
    )
    
    parser.add_argument(
        "--cwe", 
        type=str, 
        default="CWE-89",
        choices=config.SUPPORTED_CWES,
        help="要检测的CWE类型 (默认: CWE-89)"
    )
    
    parser.add_argument(
        "--config", 
        type=str,
        help="配置文件路径 (覆盖CWE默认配置)"
    )
    
    parser.add_argument(
        "--recursive", 
        action="store_true",
        help="递归分析目录"
    )
    
    parser.add_argument(
        "--output", 
        type=str,
        help="输出文件路径 (支持.sarif, .json)"
    )
    
    parser.add_argument(
        "--pretty", 
        action="store_true",
        help="美化输出"
    )
    
    parser.add_argument(
        "--verbose", 
        action="store_true",
        help="显示详细漏洞路径"
    )
    
    parser.add_argument(
        "--no-cache", 
        action="store_true",
        help="禁用缓存"
    )
    
    parser.add_argument(
        "--debug", 
        action="store_true",
        help="启用调试模式"
    )
    
    parser.add_argument(
        "--max-files", 
        type=int,
        default=1000,
        help="最大分析文件数 (默认: 1000)"
    )
    
    return parser.parse_args()


def main():
    """主函数"""
    args = parse_arguments()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("调试模式已启用")
    
    start_time = time.time()
    
    try:
        # 初始化分析流水线
        pipeline = PySafeScanPipeline(
            cwe_type=args.cwe,
            config_path=args.config,
            use_cache=not args.no_cache
        )
        
        # 执行分析
        target_path = Path(args.target)
        if not target_path.exists():
            logger.error(f"目标不存在: {target_path}")
            sys.exit(1)
        
        logger.info(f"开始分析目标: {target_path} (CWE: {args.cwe})")
        logger.info(f"CWE描述: {CWE_DESCRIPTIONS.get(args.cwe, '未知')}")
        
        if target_path.is_file() and target_path.suffix == '.py':
            # 分析单个文件
            results = pipeline.analyze_file(target_path)
        elif target_path.is_dir():
            # 分析目录
            results = pipeline.analyze_directory(
                target_path, 
                recursive=args.recursive,
                max_files=args.max_files
            )
        else:
            logger.error(f"无效的目标: {target_path} (只支持.py文件或目录)")
            sys.exit(1)
        
        # 添加统计信息
        results["stats"]["duration_seconds"] = time.time() - start_time
        results["stats"]["cwe"] = args.cwe
        results["stats"]["target"] = str(target_path)
        
        # 输出结果
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if output_path.suffix == '.sarif':
                # 生成SARIF报告
                generator = SARIFGenerator()
                generator.generate(results, output_path)
                logger.info(f"SARIF报告已保存: {output_path}")
            else:
                # 保存为JSON
                with open(output_path, 'w', encoding='utf-8') as f:
                    if args.pretty:
                        json.dump(results, f, indent=2, default=str, ensure_ascii=False)
                    else:
                        json.dump(results, f, default=str, ensure_ascii=False)
                logger.info(f"结果已保存: {output_path}")
        else:
            # 打印到控制台
            print_results(results, args.verbose)
        
        # 打印统计信息
        print_summary(results)
        
        # 返回状态码
        if results["stats"]["vulnerabilities_found"] > 0:
            sys.exit(1)  # 发现漏洞时返回1
        else:
            sys.exit(0)  # 无漏洞返回0
        
    except KeyboardInterrupt:
        logger.info("用户中断分析")
        sys.exit(130)
    except Exception as e:
        logger.error(f"分析失败: {e}", exc_info=True)
        sys.exit(1)


def print_results(results: dict, verbose: bool):
    """打印分析结果"""
    if not results.get("vulnerabilities"):
        print("\n✅ 未发现漏洞")
        return
    
    print(f"\n🔍 发现 {len(results['vulnerabilities'])} 个潜在漏洞:\n")
    
    for i, vuln in enumerate(results["vulnerabilities"], 1):
        print(f"{'='*60}")
        print(f"漏洞 #{i}: {vuln.get('cwe', 'Unknown')} - {vuln.get('severity', 'medium').upper()}")
        print(f"{'='*60}")
        print(f"文件: {vuln.get('file')}")
        print(f"行号: {vuln.get('line')}")
        print(f"\n描述: {vuln.get('description')}")
        
        if vuln.get('source'):
            src = vuln['source']
            print(f"\n📥 源: {src.get('file', '')}:{src.get('line', '')}")
            print(f"    代码: {src.get('code', '')}")
        
        if vuln.get('sink'):
            snk = vuln['sink']
            print(f"\n📤 汇: {snk.get('file', '')}:{snk.get('line', '')}")
            print(f"    代码: {snk.get('code', '')}")
        
        if verbose and vuln.get('path'):
            print(f"\n🔄 污染路径:")
            for j, step in enumerate(vuln['path'], 1):
                print(f"  {j}. {step.get('file', '')}:{step.get('line', '')}")
                print(f"     {step.get('code', '')}")
        
        if vuln.get('explanation'):
            print(f"\n🧠 LLM分析: {vuln['explanation']}")
        
        if vuln.get('recommendation'):
            print(f"\n💡 修复建议: {vuln['recommendation']}")
        
        print()


def print_summary(results: dict):
    """打印统计摘要"""
    stats = results.get("stats", {})
    print(f"\n{'='*60}")
    print("📊 分析统计")
    print(f"{'='*60}")
    print(f"扫描文件数: {stats.get('files_scanned', 0)}")
    print(f"发现漏洞: {stats.get('vulnerabilities_found', 0)}")
    print(f"LLM调用次数: {stats.get('llm_calls', 0)}")
    print(f"缓存命中: {stats.get('cache_hits', 0)}")
    print(f"API分析数: {stats.get('apis_analyzed', 0)}")
    print(f"分析耗时: {stats.get('duration_seconds', 0):.2f}秒")
    
    # 按严重性统计
    severity_counts = {}
    for vuln in results.get("vulnerabilities", []):
        sev = vuln.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    if severity_counts:
        print("\n严重性分布:")
        for sev in ["critical", "high", "medium", "low"]:
            if sev in severity_counts:
                print(f"  {sev}: {severity_counts[sev]}")


if __name__ == "__main__":
    main()
