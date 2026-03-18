"""AST分析器 - 提取API调用和函数参数"""

import ast
import logging
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional, Any, Union

logger = logging.getLogger(__name__)


class ASTAnalyzer(ast.NodeVisitor):
    """Python AST分析器，提取API调用和函数参数"""
    
    def __init__(self, file_path: Path, internal_packages: Set[str] = None):
        """
        初始化AST分析器
        
        Args:
            file_path: Python文件路径
            internal_packages: 内部包名集合
        """
        self.file_path = file_path
        self.internal_packages = internal_packages or set()
        
        # 提取结果
        self.external_api_calls: List[Dict] = []  # 外部API调用
        self.internal_functions: List[Dict] = []  # 内部函数定义
        self.imports: Dict[str, str] = {}          # 导入映射: alias -> full_name
        self.string_literals: List[Dict] = []      # 字符串常量
        
        # 当前上下文
        self.current_class = None
        self.current_function = None
        self.current_line = 0
        
        # 内置函数列表（忽略）
        self.builtins = {
            'print', 'len', 'range', 'open', 'eval', 'exec', 'input',
            'isinstance', 'type', 'str', 'int', 'float', 'list', 'dict',
            'set', 'tuple', 'bool', 'enumerate', 'zip', 'map', 'filter',
            'sum', 'min', 'max', 'abs', 'round', 'sorted', 'reversed'
        }
        
    def analyze(self) -> Dict:
        """
        分析文件，提取API调用和函数参数
        
        Returns:
            {
                "external_apis": [...],  # 外部API调用
                "internal_functions": [...] # 内部函数参数
                "string_literals": [...]    # 字符串常量
                "file": "path/to/file.py"
            }
        """
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            self.visit(tree)
            
            return {
                "external_apis": self.external_api_calls,
                "internal_functions": self.internal_functions,
                "string_literals": self.string_literals,
                "file": str(self.file_path)
            }
            
        except SyntaxError as e:
            logger.error(f"语法错误 {self.file_path}: {e}")
            return {
                "external_apis": [], 
                "internal_functions": [],
                "string_literals": [],
                "file": str(self.file_path),
                "error": str(e)
            }
        except UnicodeDecodeError as e:
            logger.error(f"编码错误 {self.file_path}: {e}")
            return {
                "external_apis": [], 
                "internal_functions": [],
                "string_literals": [],
                "file": str(self.file_path),
                "error": str(e)
            }
        except Exception as e:
            logger.error(f"分析失败 {self.file_path}: {e}")
            return {
                "external_apis": [], 
                "internal_functions": [],
                "string_literals": [],
                "file": str(self.file_path),
                "error": str(e)
            }
    
    def visit_Import(self, node: ast.Import):
        """处理 import x"""
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.imports[asname] = name
            logger.debug(f"Import: {asname} -> {name}")
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """处理 from x import y"""
        module = node.module or ''
        level = node.level  # 相对导入的层级
        
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            if module:
                if level > 0:
                    # 相对导入，转换为绝对路径
                    full_name = f".{module}.{name}" if level == 1 else f"{'.'*level}{module}.{name}"
                else:
                    full_name = f"{module}.{name}"
            else:
                full_name = name
            self.imports[asname] = full_name
            logger.debug(f"ImportFrom: {asname} -> {full_name}")
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """处理类定义"""
        old_class = self.current_class
        self.current_class = node.name
        logger.debug(f"进入类: {node.name}")
        self.generic_visit(node)
        self.current_class = old_class
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """处理函数定义"""
        self._visit_function(node)
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """处理异步函数定义"""
        self._visit_function(node)
    
    def _visit_function(self, node):
        """处理函数定义"""
        old_function = self.current_function
        self.current_function = node.name
        
        logger.debug(f"处理函数: {node.name}")
        
        # 记录内部函数参数
        func_info = {
            "name": node.name,
            "line": node.lineno,
            "params": [],
            "class": self.current_class,
            "file": str(self.file_path),
            "decorators": self._get_decorator_names(node.decorator_list)
        }
        
        # 提取参数
        args = node.args
        pos_args = args.args
        kw_args = args.kwarg
        var_args = args.vararg
        
        # 位置参数
        for arg in pos_args:
            param_info = {
                "name": arg.arg,
                "line": node.lineno,
                "type": self._get_annotation_name(arg.annotation) if arg.annotation else None,
                "function": node.name,
                "class": self.current_class,
                "file": str(self.file_path),
                "kind": "positional"
            }
            func_info["params"].append(param_info)
        
        # 可变参数 (*args)
        if var_args:
            param_info = {
                "name": var_args.arg,
                "line": node.lineno,
                "type": self._get_annotation_name(var_args.annotation) if var_args.annotation else None,
                "function": node.name,
                "class": self.current_class,
                "file": str(self.file_path),
                "kind": "varargs"
            }
            func_info["params"].append(param_info)
        
        # 关键字参数 (**kwargs)
        if kw_args:
            param_info = {
                "name": kw_args.arg,
                "line": node.lineno,
                "type": self._get_annotation_name(kw_args.annotation) if kw_args.annotation else None,
                "function": node.name,
                "class": self.current_class,
                "file": str(self.file_path),
                "kind": "kwargs"
            }
            func_info["params"].append(param_info)
        
        self.internal_functions.append(func_info)
        
        # 访问函数体
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_Call(self, node: ast.Call):
        """处理函数调用"""
        self.current_line = node.lineno
        
        # 获取被调用函数信息
        func_info = self._get_called_function_info(node.func)
        
        if func_info:
            # 判断是外部API还是内部函数
            if self._is_external_api(func_info["full_name"]):
                # 外部API调用
                call_info = {
                    "package": func_info["package"],
                    "class": func_info["class"],
                    "method": func_info["method"],
                    "full_name": func_info["full_name"],
                    "line": node.lineno,
                    "args": [],
                    "keywords": [],
                    "file": str(self.file_path),
                    "code": self._get_code_snippet(node),
                    "context": {
                        "function": self.current_function,
                        "class": self.current_class
                    }
                }
                
                # 提取位置参数信息
                for i, arg in enumerate(node.args):
                    arg_info = self._extract_argument_info(arg, i)
                    call_info["args"].append(arg_info)
                
                # 提取关键字参数
                for kw in node.keywords:
                    kw_info = {
                        "name": kw.arg,
                        "value": self._extract_argument_info(kw.value, -1),
                        "line": getattr(kw.value, 'lineno', node.lineno)
                    }
                    call_info["keywords"].append(kw_info)
                
                self.external_api_calls.append(call_info)
                logger.debug(f"外部API调用: {func_info['full_name']} 在行 {node.lineno}")
        
        self.generic_visit(node)
    
    def visit_Constant(self, node: ast.Constant):
        """处理常量"""
        if isinstance(node.value, str):
            self.string_literals.append({
                "value": node.value,
                "line": node.lineno,
                "file": str(self.file_path),
                "context": {
                    "function": self.current_function,
                    "class": self.current_class
                }
            })
        self.generic_visit(node)
    
    def _get_called_function_info(self, node) -> Optional[Dict]:
        """
        获取被调用函数的完整信息
        
        Returns:
            {
                "package": "os",
                "class": None,
                "method": "system",
                "full_name": "os.system"
            }
        """
        if isinstance(node, ast.Name):
            # 直接调用: function()
            name = node.id
            
            # 检查是否是内置函数
            if name in self.builtins:
                return None
            
            # 检查是否从模块导入
            if name in self.imports:
                full_name = self.imports[name]
            else:
                # 可能是当前模块的函数
                return None
            
            parts = full_name.split('.')
            return {
                "package": parts[0] if parts else None,
                "class": parts[1] if len(parts) > 2 else None,
                "method": parts[-1],
                "full_name": full_name
            }
            
        elif isinstance(node, ast.Attribute):
            # 属性调用: obj.method()
            obj_name = self._get_attribute_base(node.value)
            attr_name = node.attr
            
            # 构建完整名称
            if obj_name and obj_name in self.imports:
                base = self.imports[obj_name]
                full_name = f"{base}.{attr_name}"
            elif obj_name:
                # 可能是局部变量
                full_name = f"{obj_name}.{attr_name}"
            else:
                full_name = attr_name
            
            # 过滤内置模块
            if full_name.split('.')[0] in self.builtins:
                return None
            
            parts = full_name.split('.')
            return {
                "package": parts[0] if parts else None,
                "class": parts[1] if len(parts) > 2 else None,
                "method": parts[-1],
                "full_name": full_name
            }
        
        return None
    
    def _get_attribute_base(self, node) -> Optional[str]:
        """获取属性调用的基对象名"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_attribute_base(node.value)
        return None
    
    def _extract_argument_info(self, node, index: int) -> Dict:
        """提取参数信息"""
        info = {
            "index": index,
            "line": getattr(node, 'lineno', self.current_line),
            "type": None,
            "value": None,
            "is_literal": False
        }
        
        if isinstance(node, ast.Constant):
            info["type"] = "constant"
            info["value"] = node.value
            info["is_literal"] = True
            if isinstance(node.value, str):
                info["literal_type"] = "string"
            elif isinstance(node.value, (int, float)):
                info["literal_type"] = "number"
            elif node.value is None:
                info["literal_type"] = "none"
        elif isinstance(node, ast.Name):
            info["type"] = "variable"
            info["value"] = node.id
            info["is_literal"] = False
        elif isinstance(node, ast.Call):
            info["type"] = "call"
            info["is_literal"] = False
        elif isinstance(node, ast.BinOp):
            info["type"] = "expression"
            info["is_literal"] = False
        elif isinstance(node, ast.List):
            info["type"] = "list"
            info["is_literal"] = True
        elif isinstance(node, ast.Dict):
            info["type"] = "dict"
            info["is_literal"] = True
        elif isinstance(node, ast.Attribute):
            info["type"] = "attribute"
            info["value"] = self._get_attribute_base(node)
            info["is_literal"] = False
        
        return info
    
    def _get_annotation_name(self, node) -> Optional[str]:
        """获取类型注解名"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Constant):
            return str(node.value)
        return None
    
    def _get_decorator_names(self, decorators) -> List[str]:
        """获取装饰器名称列表"""
        names = []
        for dec in decorators:
            if isinstance(dec, ast.Name):
                names.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                names.append(dec.attr)
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    names.append(dec.func.id)
        return names
    
    def _get_code_snippet(self, node) -> str:
        """获取代码片段"""
        try:
            return ast.unparse(node).strip()
        except:
            return "<code>"
    
    def _is_external_api(self, full_name: str) -> bool:
        """
        判断是否为外部API
        
        规则:
        1. 不在内部包中
        2. 不是Python内置函数
        3. 不是Python标准库中不相关的模块
        """
        # 忽略Python内置函数
        if full_name in self.builtins or full_name.split('.')[0] in self.builtins:
            return False
        
        # 常见Python标准库（保留可能涉及安全的）
        safe_stdlib = {'os', 'subprocess', 'sqlite3', 'pickle', 'json', 'yaml',
                      'flask', 'django', 'requests', 'urllib', 'socket',
                      'tempfile', 'shutil', 'glob', 'pathlib'}
        
        first_part = full_name.split('.')[0]
        if first_part in safe_stdlib:
            return True
        
        # 检查是否在内部包中
        for pkg in self.internal_packages:
            if full_name.startswith(pkg):
                return False
        
        # 如果有导入记录且不是内置，认为是外部API
        return True


class ProjectAnalyzer:
    """项目级分析器，遍历所有Python文件"""
    
    def __init__(self, internal_packages: Set[str] = None):
        self.internal_packages = internal_packages or set()
        self.results = []
        self.file_count = 0
        
    def analyze_directory(self, directory: Path, recursive: bool = True, max_files: int = 1000) -> List[Dict]:
        """分析目录中的所有Python文件"""
        if recursive:
            pattern = '**/*.py'
        else:
            pattern = '*.py'
        
        files_analyzed = 0
        for py_file in directory.glob(pattern):
            if files_analyzed >= max_files:
                logger.warning(f"达到最大文件数限制 ({max_files})")
                break
                
            if py_file.is_file() and not self._should_ignore(py_file):
                logger.info(f"分析文件 [{files_analyzed+1}/{max_files}]: {py_file}")
                result = self.analyze_file(py_file)
                if result["external_apis"] or result["internal_functions"]:
                    self.results.append(result)
                files_analyzed += 1
                self.file_count = files_analyzed
        
        logger.info(f"完成分析，共分析 {files_analyzed} 个文件")
        return self.results
    
    def analyze_file(self, file_path: Path) -> Dict:
        """分析单个文件"""
        analyzer = ASTAnalyzer(file_path, self.internal_packages)
        return analyzer.analyze()
    
    def _should_ignore(self, path: Path) -> bool:
        """判断是否应该忽略该文件"""
        ignore_patterns = {
            'test_', 'tests/', 'venv/', 'env/', '.venv/', '.env/',
            '__pycache__', 'node_modules', 'dist/', 'build/',
            'examples/', 'docs/', 'migrations/'
        }
        str_path = str(path)
        return any(pattern in str_path for pattern in ignore_patterns)
    
    def get_all_external_apis(self) -> List[Dict]:
        """获取所有外部API调用"""
        apis = []
        for result in self.results:
            apis.extend(result["external_apis"])
        return apis
    
    def get_all_internal_functions(self) -> List[Dict]:
        """获取所有内部函数"""
        functions = []
        for result in self.results:
            functions.extend(result["internal_functions"])
        return functions
    
    def get_all_string_literals(self) -> List[Dict]:
        """获取所有字符串常量"""
        strings = []
        for result in self.results:
            strings.extend(result.get("string_literals", []))
        return strings
