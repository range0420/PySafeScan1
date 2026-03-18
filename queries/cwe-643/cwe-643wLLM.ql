/**
 * @name XPath injection vulnerability (CWE-643)
 * @description Detects paths where user input flows into XPath queries
 * @kind path-problem
 * @id py/xpath-injection-llm
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class XPathInjectionConfig extends TaintTracking::Configuration {
  XPathInjectionConfig() { this = "XPathInjectionConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
}

from XPathInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "XPath injection vulnerability: $@ flows to XPath query",
  source.getNode(), "User input"
