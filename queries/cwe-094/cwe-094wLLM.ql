/**
 * @name Code injection vulnerability (CWE-94)
 * @description Detects paths where user-controlled data flows into eval/exec
 * @kind path-problem
 * @id py/code-injection-llm
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class CodeInjectionConfig extends TaintTracking::Configuration {
  CodeInjectionConfig() { this = "CodeInjectionConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    exists(APICall call |
      call.getCalleeName() = "literal_eval"  // ast.literal_eval是安全的
    )
  }
}

from CodeInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Code injection vulnerability: $@ flows to eval/exec",
  source.getNode(), "User input"
