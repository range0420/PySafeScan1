/**
 * @name Path traversal vulnerability (IRIS-enhanced)
 * @description Custom path injection detection with LLM-inferred sources/sinks
 * @kind path-problem
 * @id py/path-injection-iris
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
      none()
    )
  }
}

/**
 * LLM-inferred sinks
 */
class MySink extends DataFlow::Node {
  MySink() {
    exists(DataFlow::Node sink |
      none()
    )
  }
}

/**
 * Custom taint configuration
 */
class PathInjectionConfig extends TaintTracking::Configuration {
  PathInjectionConfig() { this = "PathInjectionConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
}

from PathInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Path traversal vulnerability"
