/**
 * @name Weak encryption key (CWE-326)
 * @description Detects use of insufficient encryption key lengths
 * @kind problem
 * @id py/weak-cryptographic-key-llm
 * @problem.severity warning
 */

import python
import semmle.python.dataflow.new.DataFlow
import MySources

from DataFlow::CallNode call
where call.getCalleeName() = "generate_key" and
      call.getArg(0).(DataFlow::IntegerIntegerNode).getIntValue() < 128 and
      call.getArg(0) instanceof MySource
select call, "Weak encryption key length: " + call.getArg(0).(DataFlow::IntegerIntegerNode).getIntValue() + " bits"
