/**
 * @name Path Traversal with LLM
 * @kind path-problem
 * @problem.severity error
 * @id py/llm-path-traversal
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources 

// 假设 MySources.qll 中定义了 MyLlmModel::LlmSource
// 这里我们直接定义配置
module LlmConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof MyLlmModel::LlmSource
  }

  predicate isSink(DataFlow::Node sink) {
    // 这里使用基础的文件操作 Sink，可根据需要扩充
    exists(DataFlow::Node n | 
        sink = n and 
        n.asCfgNode().getNode() instanceof Call and
        n.asCfgNode().getNode().(Call).getFunc().(Attribute).getName() = "open"
    )
  }
}

module LlmTaintTracking = TaintTracking::Global<LlmConfig>;
import LlmTaintTracking::PathGraph

from LlmTaintTracking::PathNode source, LlmTaintTracking::PathNode sink
where LlmTaintTracking::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential path traversal from $@ to $@",
  source.getNode(), "LLM-inferred source",
  sink.getNode(), "sink"
