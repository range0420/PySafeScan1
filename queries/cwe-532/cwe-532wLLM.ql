/**
 * @name Information exposure through log files (CWE-532)
 * @description Detects logging of sensitive information
 * @kind problem
 * @id py/sensitive-log-llm
 * @problem.severity warning
 */

import python

class SensitiveDataVar extends DataFlow::Node {
  SensitiveDataVar() {
    exists(string name | this.(DataFlow::LocalSourceNode).getName() |
      name.matches("%password%") or
      name.matches("%secret%") or
      name.matches("%token%") or
      name.matches("%credit%") or
      name.matches("%ssn%")
    )
  }
}

from DataFlow::CallNode call, SensitiveDataVar data
where call.getCalleeName() in ["info", "debug", "warning", "error", "log"] and
      call.getArg(0) = data
select call, "Sensitive information written to log"
