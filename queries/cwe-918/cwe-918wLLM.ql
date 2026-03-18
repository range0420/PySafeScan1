/**
 * @name Server-side request forgery (CWE-918)
 * @description Detects paths where user-controlled data flows into URL requests
 * @kind path-problem
 * @id py/ssrf-llm
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class SSRFConfig extends TaintTracking::Configuration {
  SSRFConfig() { this = "SSRFConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    // URL验证可以阻止SSRF
    exists(APICall call |
      call.getCalleeName() = "urlparse" or
      call.getCalleeName() = "urlsplit"
    )
  }
}

from SSRFConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SSRF vulnerability: $@ flows to URL request",
  source.getNode(), "User input"
