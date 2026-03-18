/**
 * @name Get All APIs
 * @description 提取项目中所有调用的API
 * @kind problem
 * @id py/get-all-apis
 */

import python

from Call call
select call, call.getLocation().getFile().getBaseName(), call.getLocation().getStartLine()
