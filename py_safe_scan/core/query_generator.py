# py_safe_scan/core/query_generator.py
"""动态CodeQL查询生成器 - 将LLM推断的规范转换为污点分析查询"""

import logging
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class QueryGenerator:
    """动态生成CodeQL污点分析查询"""
    
    def __init__(self, query_dir: Path = None):
        """
        初始化查询生成器
        
        Args:
            query_dir: 查询输出目录
        """
        self.query_dir = query_dir or Path(__file__).parent.parent.parent / "queries" / "generated"
        self.query_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_taint_query(
        self,
        cwe_type: str,
        sources: List[Dict],
        sinks: List[Dict],
        propagators: List[Dict] = None
    ) -> Path:
        """
        生成污点分析查询
        
        Args:
            cwe_type: CWE类型
            sources: 源点列表
            sinks: 汇点列表
            propagators: 传播器列表
            
        Returns:
            生成的查询文件路径
        """
        
        # CWE到CodeQL查询模板的映射
        cwe_to_template = {
            "CWE-89": "SqlInjection.ql",
            "CWE-78": "CommandInjection.ql",
            "CWE-79": "Xss.ql",
            "CWE-22": "PathInjection.ql",
            "CWE-611": "Xxe.ql",
            "CWE-502": "UnsafeDeserialization.ql",
            "CWE-94": "CodeInjection.ql",
            "CWE-90": "LdapInjection.ql",
            "CWE-643": "XPathInjection.ql",
            "CWE-918": "Ssrf.ql"
        }
        
        template_name = cwe_to_template.get(cwe_type, "TaintTracking.ql")
        
        # 生成查询文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        query_file = self.query_dir / f"{cwe_type}_{timestamp}.ql"
        
        # 生成source谓词
        source_predicates = []
        for src in sources:
            method = src.get("method", "")
            package = src.get("package", "")
            confidence = src.get("llm_confidence", 50)
            
            if confidence < 60:  # 低置信度的不加
                continue
            
            # 处理不同的源类型
            if "flask" in package and "request" in method:
                source_predicates.append(f"""
    // Flask request parameter (LLM inferred, confidence: {confidence})
    result.asSource() and
    exists(DataFlow::Node source |
      source.asExpr().(Call).getFunction().getName() = "{method}" and
      source.asExpr().(Call).getFunction().getScope().getName() = "{package}"
    )""")
            else:
                source_predicates.append(f"""
    // {package}.{method} (LLM inferred, confidence: {confidence})
    result.asSource() and
    exists(DataFlow::Node source |
      source.asExpr().(Call).getFunction().getName() = "{method}"
    )""")
        
        # 生成sink谓词
        sink_predicates = []
        for snk in sinks:
            method = snk.get("method", "")
            package = snk.get("package", "")
            sink_args = snk.get("sink_args", [0])  # 默认第一个参数
            confidence = snk.get("llm_confidence", 50)
            
            if confidence < 60:
                continue
            
            arg_conditions = []
            for arg_idx in sink_args:
                arg_conditions.append(f"arg = call.getArg({arg_idx})")
            
            arg_condition = " or ".join(arg_conditions)
            
            sink_predicates.append(f"""
    // {package}.{method} (LLM inferred, confidence: {confidence})
    result.asSink() and
    exists(Call call, Expr arg |
      call.getFunction().getName() = "{method}" and
      ({arg_condition}) and
      arg = result.asExpr()
    )""")
        
        # 生成传播器谓词
        propagator_predicates = []
        if propagators:
            for prop in propagators:
                method = prop.get("method", "")
                package = prop.get("package", "")
                confidence = prop.get("llm_confidence", 50)
                
                if confidence < 60:
                    continue
                
                propagator_predicates.append(f"""
    // {package}.{method} (LLM inferred, confidence: {confidence})
    result.(TaintTracking::AdditionalTaintStep).step(node1, node2) and
    exists(Call call |
      call.getFunction().getName() = "{method}" and
      node1.asExpr() = call.getAnArg() and
      node2.asExpr() = call
    )""")
        
        # 读取模板
        template_path = Path(__file__).parent.parent.parent / "queries" / "templates" / template_name
        if not template_path.exists():
            # 使用默认模板
            template = self._get_default_template(cwe_type)
        else:
            with open(template_path, 'r') as f:
                template = f.read()
        
        # 替换占位符
        query_content = template.replace(
            "/* INSERT_SOURCES */",
            "\n    or\n    ".join(source_predicates) if source_predicates else "none()"
        ).replace(
            "/* INSERT_SINKS */",
            "\n    or\n    ".join(sink_predicates) if sink_predicates else "none()"
        ).replace(
            "/* INSERT_PROPAGATORS */",
            "\n    or\n    ".join(propagator_predicates) if propagator_predicates else "none()"
        )
        
        # 添加元数据
        metadata = f"""/**
 * @name {cwe_type} Taint Tracking (LLM Enhanced)
 * @description Dynamically generated taint tracking query for {cwe_type}
 * @kind path-problem
 * @id py/llm-enhanced/{cwe_type.lower()}
 */

"""
        
        query_content = metadata + query_content
        
        # 保存查询
        query_file.write_text(query_content)
        logger.info(f"生成污点分析查询: {query_file}")
        
        return query_file
    
    def _get_default_template(self, cwe_type: str) -> str:
        """获取默认查询模板"""
        return """
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

class VulnerabilityConfig extends TaintTracking::Configuration {
  VulnerabilityConfig() { this = "VulnerabilityConfig" }

  override predicate isSource(DataFlow::Node source) {
    /* INSERT_SOURCES */
  }

  override predicate isSink(DataFlow::Node sink) {
    /* INSERT_SINKS */
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    /* INSERT_PROPAGATORS */
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, VulnerabilityConfig conf
where conf.hasFlowPath(source, sink)
select sink, source, sink, "Potential vulnerability detected"
"""
