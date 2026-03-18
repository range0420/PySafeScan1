/**
 * @name SQL injection vulnerability (CWE-89)
 * @description Detects paths where user-controlled data flows into SQL execution
 * @kind path-problem
 * @id py/sql-injection-llm
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class SQLInjectionConfig extends TaintTracking::Configuration {
  SQLInjectionConfig() { this = "SQLInjectionConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    // 参数化查询是安全的
    exists(APICall call |
      call.getCalleeName() = "execute" and
      exists(call.getArg(1)) // 有参数列表，说明是参数化查询
    )
  }
}

from SQLInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection vulnerability: $@ flows to SQL execution",
  source.getNode(), "User input"
