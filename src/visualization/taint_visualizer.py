"""
污点可视化模块 - 简化版（不依赖plotly）
先实现核心功能，可视化可以后续添加
"""

import json
from typing import Dict, List, Any

class SimpleTaintVisualizer:
    """简化版污点可视化器"""
    
    def __init__(self):
        pass
    
    def generate_text_report(self, analysis_results: Dict[str, Any]) -> str:
        """生成文本报告"""
        report = []
        report.append("=" * 60)
        report.append("PySafeScan Pro - 污点分析报告")
        report.append("=" * 60)
        
        if 'file' in analysis_results:
            report.append(f"📄 分析文件: {analysis_results['file']}")
        
        if 'tainted_variables' in analysis_results:
            report.append(f"🎯 污点变量数: {analysis_results['tainted_variables']}")
        
        if 'vulnerability_paths' in analysis_results:
            paths = analysis_results['vulnerability_paths']
            report.append(f"⚠️  发现漏洞路径: {len(paths)}")
            
            if paths:
                report.append("\n🔍 漏洞传播路径:")
                for i, path in enumerate(paths, 1):
                    report.append(f"\n路径 {i}:")
                    report.append("  → " + " → ".join(path))
        
        if 'graph_edges' in analysis_results:
            edges = analysis_results['graph_edges']
            if edges:
                report.append("\n📊 污点传播关系:")
                for edge in edges[:10]:  # 只显示前10条边
                    report.append(f"  {edge[0]} → {edge[1]}")
                if len(edges) > 10:
                    report.append(f"  ... 还有 {len(edges) - 10} 条边未显示")
        
        report.append("\n" + "=" * 60)
        report.append("✅ 分析完成")
        
        return "\n".join(report)
    
    def generate_json_report(self, analysis_results: Dict[str, Any]) -> str:
        """生成JSON报告"""
        return json.dumps(analysis_results, indent=2, ensure_ascii=False)
    
    def generate_markdown_report(self, analysis_results: Dict[str, Any]) -> str:
        """生成Markdown报告"""
        md = []
        md.append("# PySafeScan Pro 污点分析报告")
        md.append("")
        
        md.append("## 📊 分析概览")
        md.append("")
        
        if 'file' in analysis_results:
            md.append(f"- **分析文件**: `{analysis_results['file']}`")
        
        if 'tainted_variables' in analysis_results:
            md.append(f"- **污点变量**: {analysis_results['tainted_variables']} 个")
        
        if 'vulnerability_paths' in analysis_results:
            paths = analysis_results['vulnerability_paths']
            md.append(f"- **漏洞路径**: {len(paths)} 条")
        
        if 'graph_edges' in analysis_results:
            edges = analysis_results['graph_edges']
            md.append(f"- **传播关系**: {len(edges)} 条")
        
        md.append("")
        
        # 漏洞详情
        if 'vulnerability_paths' in analysis_results and analysis_results['vulnerability_paths']:
            md.append("## 🔍 漏洞详情")
            md.append("")
            
            for i, path in enumerate(analysis_results['vulnerability_paths'], 1):
                md.append(f"### 漏洞 {i}")
                md.append("")
                md.append("**传播路径**:")
                md.append("")
                md.append("```")
                for step in path:
                    md.append(f"→ {step}")
                md.append("```")
                md.append("")
        
        # 污点变量
        if 'analysis_details' in analysis_results and 'sources_found' in analysis_results['analysis_details']:
            sources = analysis_results['analysis_details']['sources_found']
            if sources:
                md.append("## 🎯 污点源")
                md.append("")
                md.append("| 变量名 | 类型 | 行号 |")
                md.append("|--------|------|------|")
                for source in sources:
                    if isinstance(source, dict):
                        md.append(f"| `{source.get('name', '')}` | {source.get('type', '')} | {source.get('line', '')} |")
        
        return "\n".join(md)
    
    def export_report(self, analysis_results: Dict[str, Any], format: str = 'text', output_file: str = None):
        """导出报告"""
        if format == 'json':
            content = self.generate_json_report(analysis_results)
            ext = '.json'
        elif format == 'markdown':
            content = self.generate_markdown_report(analysis_results)
            ext = '.md'
        else:  # text
            content = self.generate_text_report(analysis_results)
            ext = '.txt'
        
        if output_file:
            # 确保文件扩展名匹配
            if not output_file.endswith(ext):
                output_file += ext
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✅ 报告已保存: {output_file}")
        else:
            print(content)
