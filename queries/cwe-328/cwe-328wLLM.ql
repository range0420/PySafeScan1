/**
 * @name Weak hash algorithm (CWE-328)
 * @description Detects use of weak or broken hash algorithms
 * @kind problem
 * @id py/weak-hash-llm
 * @problem.severity warning
 */

import python

class WeakHash extends string {
  WeakHash() {
    this in ["md5", "MD5", "sha1", "SHA1"]
  }
}

from DataFlow::CallNode call
where call.getCalleeName() = "new" and
      call.getArg(0).(DataFlow::ExprNode).getExpr().(StrConst).getValue() instanceof WeakHash
select call, "Use of weak hash algorithm: " + call.getArg(0).(DataFlow::ExprNode).getExpr().(StrConst).getValue()
