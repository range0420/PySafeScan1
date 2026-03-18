/**
 * @name Hardcoded credentials (CWE-798)
 * @description Detects hardcoded passwords or API keys
 * @kind problem
 * @id py/hardcoded-credentials-llm
 * @problem.severity error
 */

import python

from DataFlow::Node node, StrConst c
where c = node.getExpr().(StrConst) and
      c.getValue().regexpMatch("(?i).*(password|passwd|pwd|secret|key|token|apikey).*") and
      c.getValue().length() > 8
select c, "Possible hardcoded credential: '" + c.getValue() + "'"
