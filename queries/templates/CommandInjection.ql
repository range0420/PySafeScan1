# queries/templates/CommandInjection.ql
"""
/**
 * @name Command Injection (LLM Enhanced)
 * @description Detects command injection vulnerabilities with LLM-inferred sources and sinks
 * @kind path-problem
 * @id py/llm-enhanced/command-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    /* INSERT_SOURCES */
  }

  override predicate isSink(DataFlow::Node sink) {
    /* INSERT_SINKS */
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    /* INSERT_PROPAGATORS */
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, CommandInjectionConfig conf
where conf.hasFlowPath(source, sink)
select sink, source, sink, "Potential command injection vulnerability."
"""
