"""
PySafeScan 命令行接口 - 增强版（集成DeepSeek AI分析）
"""
import argparse
import sys
import os
import json
from pathlib import Path
from datetime import datetime
from visualization.html_generator import generate_report

# 添加src到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from ast_analyzer.simple_analyzer import SimplePythonAnalyzer


from context_retriever import get_enhanced_context
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
    
# AI分析阶段 (替换你代码中 if args.ai and DEEPSEEK_AVAILABLE: 之后的部分)
    if args.ai and DEEPSEEK_AVAILABLE:
        if not all_results:
            print("⚠️  未发现需要分析的API调用")
            return

        print("\n" + "="*50)
        print("🤖 DeepSeek AI安全分析阶段")
        print("="*50)

        try:
            ai_analyzer = DeepSeekSecurityAnalyzer()
            batch_size = args.batch_size
            enhanced_results = []

            for i in range(0, len(all_results), batch_size):
                batch = all_results[i:i + batch_size]
                for item in batch:
                    file_path = item.get('file') or item.get('filename')
                    line_num = item.get('line') or item.get('line_number')
                    if file_path and line_num:
                        # 触发 Jedi 跨文件上下文抓取
                        context = get_enhanced_context(file_path, int(line_num))
                        item['full_context'] = context
                
                print(f"  处理批次 {i//batch_size + 1}/{(len(all_results)-1)//batch_size + 1} ({len(batch)}个API)")
                batch_enhanced = ai_analyzer.analyze_risk_batch(batch)
                # 调试点：打印 AI 原始返回，看里面有没有 fix_code
                print(f"DEBUG AI RETURN: {batch_enhanced}")
                enhanced_results.extend(batch_enhanced)

            all_results = enhanced_results
            print(f"💡 AI分析完成! 累计估算成本: ¥{ai_analyzer.total_cost:.4f}")

            # --- 新增：自动修复逻辑 ---
            # 1. 提取所有包含修复代码的高风险项
            high_risks = [r for r in all_results if r.get('risk_level') in ['high','critical'] and r.get('fix_code')]
            print(f"DEBUG: 最终筛选出可修复的高风险项: {len(high_risks)} 个")
            # 2. 生成可视化报告
            generate_report(all_results)

            # 3. 交互式修复过程
            if high_risks:
                print(f"\n" + "🔧"*20)
                print(f"🔧 AI 修复助手: 发现 {len(high_risks)} 个可自动修复的高风险漏洞")
                print("🔧"*20)
                
                choice = input("\n👉 是否进入交互式修复模式? (y/n): ").lower()
                if choice == 'y':
                    from core.patcher import apply_fix_in_memory
    
                    # 1. 首先读取文件的当前内容到变量
                    high_risks.sort(key=lambda x: x['line'], reverse=True)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_buffer = f.read()

                    # 2. 迭代修复
                    for r in high_risks:
                        print(f"📍 正在内存中应用修复(倒序): {r['vulnerability']} at line {r['line']}")
                        # 核心逻辑：这里需要修改 apply_fix，让它支持传入字符串内容并返回修改后的字符串
                        file_buffer = apply_fix_in_memory(
                            file_buffer, 
                            r['line'], 
                            r['full_context'], 
                            r['fix_code'],
                            is_block_fix=r.get('is_block_fix', False)
                        )
                    fixed_path = f"{file_path}.fixed"
                    # 3. 最后一次性保存
                    with open(fixed_path, 'w', encoding='utf-8') as f:
                        f.write(file_buffer)
                    print(f"✨ 累积修复完成！所有高风险漏洞已整合至: {fixed_path}")
                else:
                    print("⏭️ 已跳过自动修复步骤。")

        except Exception as e:
            print(f"⚠️  AI分析失败: {e}，继续使用基础分析结果")

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
