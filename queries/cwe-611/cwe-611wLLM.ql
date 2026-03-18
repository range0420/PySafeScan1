/**
 * @name XXE injection vulnerability (CWE-611)
 * @description Detects unsafe XML parsing with user-controlled data
 * @kind path-problem
 * @id py/xxe-llm
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class XXEConfig extends TaintTracking::Configuration {
  XXEConfig() { this = "XXEConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    // 禁用外部实体的XML解析是安全的
    exists(APICall call |
      call.getCalleeName() = "parse" and
      call.getArgByName("resolve_entities").(DataFlow::ExprNode).getExpr().(Constant).getBoolean() = false
    )
  }
}

from XXEConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "XXE vulnerability: $@ flows to XML parsing",
  source.getNode(), "User input"
