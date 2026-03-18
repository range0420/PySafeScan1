/**
 * @name Cross-site scripting vulnerability (CWE-79)
 * @description Detects paths where user-controlled data flows into HTML output
 * @kind path-problem
 * @id py/xss-llm
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class XSSConfig extends TaintTracking::Configuration {
  XSSConfig() { this = "XSSConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    exists(APICall call |
      call.getCalleeName() = "escape" or
      call.getCalleeName() = "markupsafe.escape"
    )
  }
}

from XSSConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "XSS vulnerability: $@ flows to HTML output",
  source.getNode(), "User input"
