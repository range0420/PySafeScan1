/**
 * @name Insecure deserialization vulnerability (CWE-502)
 * @description Detects unsafe deserialization of user-controlled data
 * @kind path-problem
 * @id py/unsafe-deserialization-llm
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class DeserializationConfig extends TaintTracking::Configuration {
  DeserializationConfig() { this = "DeserializationConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    // yaml.safe_load 比 yaml.load 安全
    exists(APICall call |
      call.getCalleeName() = "safe_load"
    )
  }
}

from DeserializationConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Insecure deserialization: $@ flows to deserialization",
  source.getNode(), "User input"
