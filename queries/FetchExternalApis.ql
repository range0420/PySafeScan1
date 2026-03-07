/**
 * @name Fetch External APIs
 * @description 提取项目中调用的所有外部API
 * @kind problem
 * @id py/fetch-external-apis
 */

import python
import semmle.python.Exprs
import semmle.python.Function
import semmle.python.Modules

from Call call
where exists(call.getFunction()) and
      call.getFunction().getScope().getEnclosingModule().isExternal()
select call,
       call.getFunction().getName() as method,
       call.getLocation().getFile().toString() as file,
       call.getLocation().getStartLine() as line
