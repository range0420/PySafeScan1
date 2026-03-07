/**
 * @name Fetch Documentation
 * @description 提取项目中的文档字符串
 * @kind problem
 * @id py/fetch-documentation
 */

import python
import semmle.python.Modules

from Module m
where not m.isExternal() and
      exists(m.getDocstring())
select m,
       m.getName() as module,
       m.getLocation().getFile().toString() as file,
       m.getDocstring() as docstring
