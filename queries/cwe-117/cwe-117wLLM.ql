/**
 * @name Log injection vulnerability (CWE-117)
 * @description Detects paths where user input flows into log entries without sanitization
 * @kind path-problem
 * @id py/log-injection-llm
 * @problem.severity warning
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class LogInjectionConfig extends TaintTracking::Configuration {
  LogInjectionConfig() { this = "LogInjectionConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    exists(APICall call |
      call.getCalleeName() = "replace" and
      call.getArg(0).(DataFlow::ExprNode).getExpr().(StrConst).getValue().regexpMatch("[\n\r]")
    )
  }
}

from LogInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Log injection vulnerability: $@ flows to log entry",
  source.getNode(), "User input"
