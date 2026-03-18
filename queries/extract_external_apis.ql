/**
 * @name Extract external APIs
 * @description Extract all external API calls from the codebase
 * @kind problem
 * @id py/extract-external-apis
 */

import python

/**
 * Get the package name of a value
 */
string getPackageName(Value v) {
  exists(Module m | v = m.getVariable().getAValue() |
    result = m.getName()
  )
  or
  exists(Class cls | v = cls.getVariable().getAValue() |
    result = cls.getScope().getName()
  )
}

/**
 * Get the class name of a value
 */
string getClassName(Value v) {
  exists(Class cls | v = cls.getVariable().getAValue() |
    result = cls.getName()
  )
}

/**
 * Get the function name
 */
string getFunctionName(Value v) {
  exists(Function f | v = f.getVariable().getAValue() |
    result = f.getName()
  )
}

/**
 * Get the call line number
 */
int getCallLine(Call c) {
  result = c.getLocation().getStartLine()
}

/**
 * Get the call file name
 */
string getCallFile(Call c) {
  result = c.getLocation().getFile().getBaseName()
}

/**
 * Get the call code
 */
string getCallCode(Call c) {
  result = c.toString()
}

/**
 * Extract all external API calls
 * An external API is a call to a function not defined in the source code
 */
from Call call, Value func
where call.getFunction() = func and
      not func.fromSource() and
      not func.isBuiltin() and
      func.getName() != ""
select 
  getPackageName(func) as package,
  getClassName(func) as class,
  getFunctionName(func) as method,
  getCallLine(call) as line,
  getCallFile(call) as file,
  getCallCode(call) as code
