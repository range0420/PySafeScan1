/**
 * @name Path traversal vulnerability (LLM-enhanced)
 * @description Detects paths where user-controlled data flows into file operations
 * @kind path-problem
 * @problem.severity error
 * @id py/path-injection-llm
 * @tags security
 *       external/cwe/cwe-022
 */

import python
import semmle.python.security.dataflow.PathInjectionQuery
import PathInjectionFlow::PathGraph

from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where PathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Path traversal vulnerability"
