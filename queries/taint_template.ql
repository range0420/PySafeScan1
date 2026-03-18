/**
 * @name {{ cwe }} Taint Tracking
 * @description Taint tracking for {{ cwe }} vulnerabilities
 * @kind path-problem
 * @id py/{{ cwe_id }}/taint
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.GlobalDataFlow

/**
 * 从LLM推断的源规范
 */
predicate isLlmSource(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    // 这里是动态生成的源匹配规则
    {{ source_predicates }}
  )
}

/**
 * 从LLM推断的汇规范
 */
predicate isLlmSink(DataFlow::Node node) {
  exists(DataFlow::CallNode call, int argIndex |
    // 这里是动态生成的汇匹配规则
    {{ sink_predicates }}
  )
}

/**
 * 污点跟踪配置
 */
module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isLlmSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isLlmSink(sink)
  }
  
  // 可以添加自定义的污点传播规则
  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // 处理字符串操作等传播
    any()
  }
}

module TaintFlow = TaintTracking::Global<TaintConfig>;

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted data flows from $@ to this sink.",
  source.getNode(), "here"
