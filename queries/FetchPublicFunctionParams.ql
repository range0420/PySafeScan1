/**
 * @name Fetch Public Function Parameters
 * @description 提取项目中所有公开函数的参数
 * @kind problem
 * @id py/fetch-public-function-params
 */

import python
import semmle.python.Function
import semmle.python.Modules

from Function f
where not f.getScope().getEnclosingModule().isExternal() and
      f.isPublic()
select f,
       f.getName() as name,
       f.getLocation().getFile().toString() as file,
       f.getLocation().getStartLine() as line,
       count(f.getArg(_)) as param_count
