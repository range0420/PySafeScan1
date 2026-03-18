# queries/templates/SqlInjection.ql
"""
/**
 * @name SQL Injection (LLM Enhanced)
 * @description Detects SQL injection vulnerabilities with LLM-inferred sources and sinks
 * @kind path-problem
 * @id py/llm-enhanced/sql-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

/**
 * A taint tracking configuration for SQL injection
 */
class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

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

from DataFlow::PathNode source, DataFlow::PathNode sink, SqlInjectionConfig conf
where conf.hasFlowPath(source, sink)
select sink, source, sink, "Potential SQL injection vulnerability."
"""
