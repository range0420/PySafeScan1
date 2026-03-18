/**
 * @name Path Traversal with LLM Guidance
 * @kind path-problem
 * @problem.severity error
 * @id py/llm-guided-path-traversal
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import MySources

module LlmConfig implements DataFlow::ConfigSig {
  /** 定义Source：来自LLM推断的MySources库 */
  predicate isSource(DataFlow::Node source) {
    source instanceof MyLlmModel::LlmSource
  }

  /** 定义Sink：常见的文件系统写入点 */
  predicate isSink(DataFlow::Node sink) {
    exists(FileSystemAccess fs | 
      sink = fs.getAPathArgument()
    )
  }
}

/** 实例化污点分析模块 */
module LlmTaintTracking = TaintTracking::Global<LlmConfig>;
import LlmTaintTracking::PathGraph

from LlmTaintTracking::PathNode source, LlmTaintTracking::PathNode sink
where LlmTaintTracking::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential path traversal from $@ to $@", 
  source.getNode(), "LLM-inferred source", 
  sink.getNode(), "file system sink"
