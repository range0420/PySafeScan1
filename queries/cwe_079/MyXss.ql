/**
 * @name XSS vulnerability (IRIS-enhanced)
 * @description Custom XSS detection with LLM-inferred sources/sinks
 * @kind path-problem
 * @id py/xss-iris
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * LLM-inferred sources
 */
class MySource extends DataFlow::Node {
  MySource() {
    exists(DataFlow::Node src |
      none()  // source
    )
  }
}

/**
 * LLM-inferred sinks
 */
class MySink extends DataFlow::Node {
  MySink() {
    exists(DataFlow::Node sink |
      none()  // sink
    )
  }
}

/**
 * Custom taint configuration
 */
class XssConfig extends TaintTracking::Configuration {
  XssConfig() { this = "XssConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
}

from XssConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "XSS vulnerability"
