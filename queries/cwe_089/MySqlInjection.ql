/**
 * @name SQL injection vulnerability (IRIS-enhanced)
 * @description Custom SQL injection detection with LLM-inferred sources/sinks
 * @kind path-problem
 * @id py/sql-injection-iris
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
class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection vulnerability"
