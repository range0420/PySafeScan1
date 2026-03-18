/**
 * @name Command injection vulnerability (CWE-78)
 * @description Detects paths where user-controlled data flows into command execution
 * @kind path-problem
 * @id py/command-injection-llm
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    // shlex.quote 可以阻止命令注入
    exists(APICall call |
      call.getCalleeName() = "quote" and
      call.getLocation().getFile().getBaseName().matches("%shlex%")
    )
  }
  
  // 如果使用shell=False，则是安全的
  override predicate isBarrier(DataFlow::Node node) {
    exists(APICall call |
      call.getCalleeName() = "Popen" or
      call.getCalleeName() = "run" or
      call.getCalleeName() = "call"
    |
      call.getArgByName("shell").(DataFlow::ExprNode).getExpr().(Constant).getBoolean() = false
    )
  }
}

from CommandInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Command injection vulnerability: $@ flows to command execution",
  source.getNode(), "User input"
