/**
 * @name Weak random number generator (CWE-330)
 * @description Detects use of insecure random number generators
 * @kind problem
 * @id py/weak-random-llm
 * @problem.severity warning
 */

import python

from DataFlow::CallNode call
where call.getCalleeName() in ["random", "randint", "uniform"] and
      call.getLocation().getFile().getBaseName().matches("%random%")
select call, "Use of weak random number generator (random module)"
