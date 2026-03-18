/**
 * @name Broken or risky cryptographic algorithm (CWE-327)
 * @description Detects use of weak or broken cryptographic algorithms
 * @kind problem
 * @id py/weak-crypto-llm
 * @problem.severity warning
 */

import python

class InsecureCryptoAlgo extends string {
  InsecureCryptoAlgo() {
    this in ["DES", "MD2", "MD4", "MD5", "RC2", "RC4", "SHA0", "SHA1"]
  }
}

from DataFlow::CallNode call
where call.getCalleeName() = "new" and
      call.getArg(0).(DataFlow::ExprNode).getExpr().(StrConst).getValue() instanceof InsecureCryptoAlgo
select call, "Use of insecure cryptographic algorithm: " + call.getArg(0).(DataFlow::ExprNode).getExpr().(StrConst).getValue()
