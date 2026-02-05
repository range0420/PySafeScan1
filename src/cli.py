"""
PySafeScan 命令行接口
"""

import argparse
import sys
import os
from pathlib import Path

# 添加src到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ast_analyzer.simple_analyzer import SimplePythonAnalyzer

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="PySafeScan - Python代码安全扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s scan example.py          # 扫描单个文件
  %(prog)s scan ./project           # 扫描整个目录
  %(prog)s test                     # 运行测试
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # scan 命令
    scan_parser = subparsers.add_parser("scan", help="扫描代码")
    scan_parser.add_argument("path", help="文件或目录路径")
    scan_parser.add_argument("--output", "-o", help="输出文件路径")
    scan_parser.add_argument("--format", choices=["text", "json"], default="text", 
                           help="输出格式")
    
    # test 命令
    test_parser = subparsers.add_parser("test", help="运行测试")
    
    # version 命令
    version_parser = subparsers.add_parser("version", help="显示版本")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        run_scan(args)
    elif args.command == "test":
        run_test()
    elif args.command == "version":
        print("PySafeScan v0.1.0")
    else:
        parser.print_help()

def run_scan(args):
    """运行扫描"""
    path = Path(args.path)
    
    if not path.exists():
        print(f"错误: 路径不存在 {args.path}")
        return
    
    analyzer = SimplePythonAnalyzer()
    all_results = []
    
    if path.is_file() and path.suffix == ".py":
        # 扫描单个文件
        print(f"扫描文件: {path}")
        results = analyzer.analyze_file(str(path))
        all_results.extend(results)
        
    elif path.is_dir():
        # 扫描目录
        print(f"扫描目录: {path}")
        python_files = list(path.rglob("*.py"))
        
        for i, py_file in enumerate(python_files, 1):
            print(f"  [{i}/{len(python_files)}] 分析: {py_file.relative_to(path)}")
            results = analyzer.analyze_file(str(py_file))
            all_results.extend(results)
    
    # 输出结果
    print(f"\n{'='*50}")
    print(f"扫描完成! 发现 {len(all_results)} 个潜在危险调用")
    print(f"{'='*50}")
    
    for result in all_results:
        print(f"[{result['filename']}:{result['line']}] {result['function']}")
        print(f"  代码: {result['code']}")
        print()
    
    # 如果指定了输出文件
    if args.output:
        save_results(all_results, args.output, args.format)

def save_results(results, output_path, format_type):
    """保存结果"""
    try:
        if format_type == "json":
            import json
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        else:
            with open(output_path, 'w', encoding='utf-8') as f:
                for result in results:
                    f.write(f"[{result['filename']}:{result['line']}] {result['function']}\n")
                    f.write(f"  代码: {result['code']}\n\n")
        
        print(f"结果已保存到: {output_path}")
    except Exception as e:
        print(f"保存结果时出错: {e}")

def run_test():
    """运行测试"""
    from ast_analyzer.simple_analyzer import test_simple_analyzer
    print("运行简单分析器测试...")
    results = test_simple_analyzer()
    print(f"测试完成，找到 {len(results)} 个危险调用")

if __name__ == "__main__":
    main()
