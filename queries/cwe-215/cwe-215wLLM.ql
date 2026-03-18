/**
 * @name Debug information exposure (CWE-215)
 * @description Detects debug mode enabled in production
 * @kind problem
 * @id py/flask-debug-llm
 * @problem.severity warning
 */

import python

from DataFlow::CallNode call
where call.getCalleeName() = "run" and
      exists(call.getArgByName("debug").(DataFlow::ExprNode).getExpr().(Constant).getBoolean() = true)
select call, "Flask debug mode enabled - may expose sensitive information"
