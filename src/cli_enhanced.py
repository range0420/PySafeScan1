"""
增强版CLI - 集成污点追踪功能
"""

import argparse
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.core.taint_analysis import AdvancedTaintTracker
from src.visualization.taint_visualizer import TaintVisualizer

def add_taint_commands(parser):
    """添加污点追踪相关命令"""
    subparsers = parser.add_subparsers(dest='taint_command', help='污点追踪命令')
    
    # taint scan 命令
    taint_parser = subparsers.add_parser('taint', help='运行污点追踪分析')
    taint_parser.add_argument('path', help='文件或目录路径')
    taint_parser.add_argument('--visualize', action='store_true', help='生成可视化报告')
    taint_parser.add_argument('--output', '-o', help='输出报告文件')
    taint_parser.add_argument('--format', choices=['json', 'html', 'text'], 
                            default='text', help='输出格式')
    
    # taint demo 命令
    demo_parser = subparsers.add_parser('taint-demo', help='运行污点追踪演示')
    
    return parser

def run_taint_analysis(args):
    """运行污点分析"""
    print("🔍 启动污点追踪分析...")
    print("=" * 50)
    
    tracker = AdvancedTaintTracker()
    
    if os.path.isfile(args.path):
        # 单文件分析
        from src.core.taint_analysis import TaintAnalysis
        analyzer = TaintAnalysis()
        result = analyzer.analyze_file(args.path)
        
        print(f"📄 分析文件: {args.path}")
        print(f"🎯 发现污点变量: {result.get('tainted_variables', 0)}")
        print(f"⚠️  发现漏洞路径: {len(result.get('vulnerability_paths', []))}")
        
        # 显示漏洞路径
        for i, path in enumerate(result.get('vulnerability_paths', []), 1):
            print(f"\n漏洞路径 {i}:")
            print("  → " + " → ".join(path))
        
    elif os.path.isdir(args.path):
        # 项目分析
        results = tracker.analyze_project(args.path)
        
        summary = results['summary']
        print(f"📁 分析项目: {args.path}")
        print(f"📄 扫描文件: {summary['total_files']}")
        print(f"⚠️  发现漏洞: {summary['total_vulnerabilities']}")
        print(f"🎯 有漏洞文件: {summary['files_with_vulns']}")
        
        if summary['vulnerability_types']:
            print("\n漏洞类型分布:")
            for vuln_type, count in summary['vulnerability_types'].items():
                print(f"  {vuln_type}: {count}")
    
    # 可视化
    if args.visualize:
        print("\n📊 生成可视化报告...")
        visualizer = TaintVisualizer()
        
        # 这里需要实际的分析数据
        sample_data = {
            'vulnerability_paths': [],
            'vulnerability_types': {'command_injection': 2}
        }
        
        if args.format == 'html':
            output_file = args.output or 'taint_analysis.html'
            visualizer.export_dashboard(sample_data, output_file)
            print(f"✅ 可视化报告已保存: {output_file}")
    
    print("\n" + "=" * 50)
    print("✅ 污点分析完成!")

def main():
    parser = argparse.ArgumentParser(
        description='PySafeScan Pro - AI赋能的智能代码安全分析平台',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s taint example.py          # 污点分析单个文件
  %(prog)s taint ./project --visualize  # 可视化污点分析
  %(prog)s taint-demo                # 运行污点追踪演示
        '''
    )
    
    parser = add_taint_commands(parser)
    
    # 原有scan命令
    parser.add_argument('scan', nargs='?', help='传统扫描模式')
    
    args = parser.parse_args()
    
    if args.taint_command == 'taint':
        run_taint_analysis(args)
    elif args.taint_command == 'taint-demo':
        os.system('python demo_taint.py')
    else:
        # 原有逻辑
        from cli import main as original_main
        original_main()

if __name__ == '__main__':
    main()
