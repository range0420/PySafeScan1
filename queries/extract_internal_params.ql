/**
 * @name Extract internal function parameters
 * @description Extract parameters of internal public functions
 * @kind problem
 * @id py/extract-internal-params
 */

import python

/**
 * Get function name
 */
string getFunctionName(Function f) {
  result = f.getName()
}

/**
 * Get function class
 */
string getFunctionClass(Function f) {
  result = f.getScope().getName()
}

/**
 * Get parameter name
 */
string getParameterName(Parameter p) {
  result = p.getName()
}

/**
 * Get parameter position
 */
int getParameterPosition(Parameter p) {
  result = p.getIndex()
}

/**
 * Get function file
 */
string getFunctionFile(Function f) {
  result = f.getLocation().getFile().getBaseName()
}

/**
 * Get function line
 */
int getFunctionLine(Function f) {
  result = f.getLocation().getStartLine()
}

/**
 * Extract internal public function parameters
 */
from Function f, Parameter p
where f.fromSource() and
      f.isPublic() and
      p = f.getAParameter() and
      not f.getName().matches("__%")
select 
  getFunctionClass(f) as class,
  getFunctionName(f) as function,
  getParameterName(p) as param_name,
  getParameterPosition(p) as param_index,
  getFunctionLine(f) as line,
  getFunctionFile(f) as file
