/**
 * @name CWE-79 vulnerability (LLM-enhanced)
 * @description Detects CWE-79 vulnerabilities using LLM-inferred specifications
 * @kind path-problem
 * @id py/cwe-79-llm
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class VulnConfig extends TaintTracking::Configuration {
  VulnConfig() { this = "VulnConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
}

from VulnConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "CWE-79 vulnerability detected"
