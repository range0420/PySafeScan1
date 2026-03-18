/**
 * @name LDAP injection vulnerability (CWE-90)
 * @description Detects paths where user-controlled data flows into LDAP queries
 * @kind path-problem
 * @id py/ldap-injection-llm
 * @problem.severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks

class LDAPInjectionConfig extends TaintTracking::Configuration {
  LDAPInjectionConfig() { this = "LDAPInjectionConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof MySource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MySink
  }
}

from LDAPInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "LDAP injection vulnerability: $@ flows to LDAP query",
  source.getNode(), "User input"
