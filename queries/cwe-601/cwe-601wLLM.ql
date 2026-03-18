/**
 * @name URL redirection vulnerability (CWE-601)
 * @description Detects paths where user-controlled data flows into redirect URLs
 * @kind path-problem
 * @id py/url-redirect-llm
 * @problem.severity warning
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class RedirectConfig extends TaintTracking::Configuration {
  RedirectConfig() { this = "RedirectConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    // 检查URL是否在允许的域名列表中
    exists(APICall call |
      call.getCalleeName() = "urlparse" and
      call.getArg(0).(DataFlow::ExprNode).getExpr().(StrConst).getValue().regexpMatch("^https?://trusted-domain\\.com/.*")
    )
  }
}

from RedirectConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Open redirect vulnerability: $@ flows to redirect URL",
  source.getNode(), "User input"
