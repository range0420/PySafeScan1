/**
 * @name Cleartext storage of sensitive information (CWE-312)
 * @description Detects storage of sensitive data without encryption
 * @kind problem
 * @id py/cleartext-storage-llm
 * @problem.severity warning
 */

import python

class SensitiveDataVar extends DataFlow::Node {
  SensitiveDataVar() {
    exists(string name | this.(DataFlow::LocalSourceNode).getName() |
      name.matches("%password%") or
      name.matches("%secret%") or
      name.matches("%token%") or
      name.matches("%key%")
    )
  }
}

from DataFlow::CallNode call, SensitiveDataVar data
where call.getCalleeName() in ["write", "save", "dump"] and
      call.getArg(0) = data
select call, "Sensitive data written to file without encryption"
