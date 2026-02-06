"""
PySafeScan 命令行接口 - 增强版（集成DeepSeek AI分析）
"""
import argparse
import sys
import os
import json
from pathlib import Path
from datetime import datetime

# 添加src到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ast_analyzer.simple_analyzer import SimplePythonAnalyzer
# 导入新增的DeepSeek分析器
try:
    from llm_integration.deepseek_api import DeepSeekSecurityAnalyzer
    DEEPSEEK_AVAILABLE = True
except ImportError:
    print("⚠️  DeepSeek模块未找到，将仅进行基础分析")
    DEEPSEEK_AVAILABLE = False

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="PySafeScan - Python代码AI安全扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s scan example.py                    # 扫描单个文件
  %(prog)s scan ./project --ai                # 使用AI分析整个目录
  %(prog)s scan example.py --output report.json  # 输出JSON报告
  %(prog)s test                               # 运行测试
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # scan 命令（增强版）
    scan_parser = subparsers.add_parser("scan", help="扫描代码文件或目录")
    scan_parser.add_argument("path", help="Python文件或目录路径")
    scan_parser.add_argument("--ai", action="store_true", help="启用DeepSeek AI分析")
    scan_parser.add_argument("--output", "-o", help="输出报告文件路径")
    scan_parser.add_argument("--format", choices=["text", "json", "summary"], 
                           default="text", help="输出格式")
    scan_parser.add_argument("--batch-size", type=int, default=10,
                           help="AI批量分析大小（默认: 10）")
    
    # test 命令
    test_parser = subparsers.add_parser("test", help="运行测试")
    
    # version 命令
    version_parser = subparsers.add_parser("version", help="显示版本")
    
    # ai-test 命令（新增）
    ai_test_parser = subparsers.add_parser("ai-test", help="测试DeepSeek AI功能")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        run_scan(args)
    elif args.command == "test":
        run_test()
    elif args.command == "version":
        print("PySafeScan v0.2.0 - 集成DeepSeek AI分析")
    elif args.command == "ai-test":
        run_ai_test()
    else:
        parser.print_help()

def run_scan(args):
    """运行扫描（集成AI分析）"""
    path = Path(args.path)
    if not path.exists():
        print(f"❌ 错误: 路径不存在 {args.path}")
        return
    
    # 初始化分析器
    print("🔍 初始化代码分析器...")
    analyzer = SimplePythonAnalyzer()
    
    all_results = []
    
    # 收集所有Python文件
    if path.is_file() and path.suffix == ".py":
        python_files = [path]
        print(f"📄 扫描单个文件: {path}")
    elif path.is_dir():
        python_files = list(path.rglob("*.py"))
        print(f"📁 扫描目录: {path} (找到 {len(python_files)} 个Python文件)")
    else:
        print(f"❌ 错误: 不支持的文件类型")
        return
    
    # 分析每个文件
    for i, py_file in enumerate(python_files, 1):
        print(f"  [{i}/{len(python_files)}] 分析: {py_file.relative_to(path) if path.is_dir() else py_file.name}")
        results = analyzer.analyze_file(str(py_file))
        all_results.extend(results)
    
    print(f"\n✅ 基础分析完成! 发现 {len(all_results)} 个潜在危险API调用")
    
    # AI分析阶段
    if args.ai and DEEPSEEK_AVAILABLE:
        if not all_results:
            print("⚠️  未发现需要分析的API调用")
            return

        print("\n" + "="*50)
        print("🤖 DeepSeek AI安全分析阶段")
        print("="*50)

        try:
            ai_analyzer = DeepSeekSecurityAnalyzer()

            # 分批处理API调用（控制token消耗）
            batch_size = args.batch_size
            enhanced_results = []

            for i in range(0, len(all_results), batch_size):
                batch = all_results[i:i + batch_size]
                print(f"  处理批次 {i//batch_size + 1}/{(len(all_results)-1)//batch_size + 1} ({len(batch)}个API)")

                batch_enhanced = ai_analyzer.analyze_risk_batch(batch)
                enhanced_results.extend(batch_enhanced)

            all_results = enhanced_results
            print(f"💡 AI分析完成! 累计估算成本: ¥{ai_analyzer.total_cost:.4f}")
        except Exception as e:
            print(f"⚠️  AI分析失败: {e}，继续使用基础分析结果")
    
    elif args.ai and not DEEPSEEK_AVAILABLE:
        print("⚠️  DeepSeek模块不可用，请先完成API集成")
    
    # 输出结果
    print(f"\n{'='*60}")
    print(f"📊 扫描报告摘要")
    print(f"{'='*60}")
    
    # 统计信息
    if any('risk_level' in r for r in all_results):
        high_risk = sum(1 for r in all_results if r.get('risk_level') == 'high')
        medium_risk = sum(1 for r in all_results if r.get('risk_level') == 'medium')
        ai_analyzed = sum(1 for r in all_results if r.get('ai_analyzed', False))

        print(f"高风险: {high_risk} 个 | 中风险: {medium_risk} 个 | AI深度分析: {ai_analyzed} 个")
    
    print(f"总共发现: {len(all_results)} 个问题")
    
    # 按格式输出
    if args.format == "json":
        output_data = {
            "project": str(path),
            "scan_time": datetime.now().isoformat(),
            "statistics": {
                "total_apis": len(all_results),
                "high_risk": high_risk if 'high_risk' in locals() else 0,
                "medium_risk": medium_risk if 'medium_risk' in locals() else 0,
                "ai_analyzed": ai_analyzed if 'ai_analyzed' in locals() else 0
            },
            "vulnerabilities": all_results
        }

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            print(f"📁 JSON报告已保存: {args.output}")
        else:
            print(json.dumps(output_data, indent=2, ensure_ascii=False)[:1000] + "...")
    
    elif args.format == "summary":
        # 摘要输出
        for result in all_results[:20]:  # 只显示前20个
            risk_icon = "🔴" if result.get('risk_level') == 'high' else "🟡" if result.get('risk_level') == 'medium' else "⚪"
            filename = result.get('file', result.get('filename', 'unknown'))
            line = result.get('line', '?')
            print(f"{risk_icon} [{result.get('risk_level', 'unknown').upper()}] {filename}:{line}")
            print(f"   调用: {result.get('api', result.get('function', ''))[:80]}{'...' if len(result['api']) > 80 else ''}")
            if 'suggestion' in result:
                print(f"   建议: {result['suggestion']}")
            print()

        if len(all_results) > 20:
            print(f"... 还有 {len(all_results) - 20} 个问题未显示")
    else:  # text格式（默认）
        for result in all_results[:50]:  # 只显示前50个
            filename = result.get('file', result.get('filename', 'unknown'))
            line = result.get('line', '?')
            api_call = result.get('api') or result.get('function', 'unknown')
            print(f"[{filename}:{line}] {api_call}")

            if 'category' in result:
                print(f"  分类: {result.get('category', 'N/A')} | 风险: {result.get('risk_level', 'N/A')}")
                print(f"  漏洞类型: {result.get('vulnerability', 'N/A')}")
                if 'suggestion' in result:
                    print(f"  修复建议: {result['suggestion']}")
            print()

        if len(all_results) > 50:
            print(f"... 还有 {len(all_results) - 50} 个问题未显示")
    
    # 保存结果（如果指定了输出文件但不是JSON格式）
    if args.output and args.format != "json":
        save_results(all_results, args.output, args.format)

def save_results(results, output_path, format_type):
    """保存结果到文件"""
    try:
        if format_type == "json":
            # 已在主函数处理
            pass
        else:
            with open(output_path, 'w', encoding='utf-8') as f:
                for result in results:
                    filename = result.get('file', result.get('filename', 'unknown'))
                    line = result.get('line', '?')
                    api_call = result.get('api') or result.get('function', 'unknown')
                    f.write(f"[{filename}:{line}] {api_call}\n")
                    f.write(f"  代码: {result.get('code', 'N/A')}\n")
                    if 'suggestion' in result:
                        f.write(f"  建议: {result['suggestion']}\n")
                    f.write("\n")

        print(f"📄 报告已保存到: {output_path}")
    except Exception as e:
        print(f"❌ 保存结果时出错: {e}")

def run_test():
    """运行测试"""
    from ast_analyzer.simple_analyzer import test_simple_analyzer
    print("🧪 运行简单分析器测试...")
    results = test_simple_analyzer()
    print(f"✅ 测试完成，找到 {len(results)} 个危险调用")

def run_ai_test():
    """测试DeepSeek AI功能"""
    if not DEEPSEEK_AVAILABLE:
        print("❌ DeepSeek模块不可用，请先完成API集成")
        return
    
    print("🤖 测试DeepSeek AI分析功能...")
    try:
        analyzer = DeepSeekSecurityAnalyzer()
        analyzer.quick_test()
    except Exception as e:
        print(f"❌ AI测试失败: {e}")

if __name__ == "__main__":
    main()
