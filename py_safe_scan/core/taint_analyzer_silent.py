"""污点分析引擎 - 静默版本 - 追踪从源到汇的数据流"""

import ast
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Any, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class TaintNode:
    """污点节点"""
    
    def __init__(self, node_type: str, file_path: str, line: int, code: str = ""):
        self.type = node_type
        self.file = file_path
        self.line = line
        self.code = code
        self.data = {}
        self.variable = None
        
    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "file": self.file,
            "line": self.line,
            "code": self.code,
            "variable": self.variable,
            "data": self.data
        }


class TaintPath:
    """污点路径"""
    
    def __init__(self, source: Dict):
        self.source = source
        self.sink = None
        self.nodes: List[TaintNode] = []
        self.sanitized = False
        self.confidence = 0.0
        
    def add_node(self, node: TaintNode):
        self.nodes.append(node)
        
    def set_sink(self, sink: Dict):
        self.sink = sink
        
    def to_dict(self) -> Dict:
        return {
            "source": self.source,
            "sink": self.sink,
            "nodes": [n.to_dict() for n in self.nodes],
            "sanitized": self.sanitized,
            "confidence": self.confidence,
            "length": len(self.nodes)
        }


class TaintTracker(ast.NodeVisitor):
    """污点追踪器 - 静默版本"""
    
    def __init__(self, file_path: str, content: str, sources: List[Dict], sinks: List[Dict], propagators: List[Dict]):
        self.file_path = file_path
        self.content = content
        self.sources = sources
        self.sinks = sinks
        self.propagators = propagators
        
        self.tainted_vars = defaultdict(list)
        self.paths: List[TaintPath] = []
        self.current_function = None
        self.lines = content.split('\n')
        
    def get_code_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno-1].strip()
        return ""
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)
        
    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                
                if isinstance(node.value, ast.Call):
                    self._check_call_arguments_for_sources(node.value)
                    self._check_call_source_or_propagator(var_name, node.value, node.lineno)
                    
                elif isinstance(node.value, ast.Name):
                    right_var = node.value.id
                    if right_var in self.tainted_vars:
                        self.tainted_vars[var_name] = self.tainted_vars[right_var].copy()
                        
                        for path in self.paths:
                            if path.nodes and path.nodes[-1].variable == right_var:
                                new_node = TaintNode("intermediate", self.file_path, node.lineno, 
                                                   self.get_code_line(node.lineno))
                                new_node.variable = var_name
                                new_node.data = {"from_var": right_var}
                                path.add_node(new_node)
        
        self.generic_visit(node)
    
    def _check_call_arguments_for_sources(self, call_node: ast.Call):
        for arg in call_node.args:
            if isinstance(arg, ast.Call):
                self._check_call_arguments_for_sources(arg)
                
                if isinstance(arg.func, ast.Name):
                    inner_func = arg.func.id
                elif isinstance(arg.func, ast.Attribute):
                    inner_func = arg.func.attr
                else:
                    continue
                
                temp_var = f"_temp_{arg.lineno}"
                self._check_call_source_or_propagator(temp_var, arg, arg.lineno)
    
    def visit_AugAssign(self, node: ast.AugAssign):
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        full_call_chain = self._get_full_call_chain(node)
        
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        else:
            func_name = "unknown"
        
        self._check_sink(node, full_call_chain)
        self.generic_visit(node)
    
    def visit_JoinedStr(self, node: ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if isinstance(value.value, ast.Name):
                    var_name = value.value.id
                    if var_name in self.tainted_vars:
                        for path in self.paths:
                            if path.nodes and path.nodes[-1].variable == var_name:
                                new_node = TaintNode("intermediate", self.file_path, node.lineno,
                                                   self.get_code_line(node.lineno))
                                new_node.variable = var_name
                                new_node.data = {"in_fstring": True}
                                path.add_node(new_node)
        self.generic_visit(node)
    
    def _get_full_call_chain(self, call_node: ast.Call) -> str:
        try:
            return ast.unparse(call_node.func)
        except:
            return ""
    
    def _check_call_source_or_propagator(self, var_name: str, call_node: ast.Call, lineno: int):
        """检查函数调用是否为源或传播器"""
        full_call_chain = self._get_full_call_chain(call_node)
        
        if isinstance(call_node.func, ast.Name):
            func_name = call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            func_name = call_node.func.attr
        else:
            func_name = "unknown"
        
        # 检查参数中是否有污点变量
        tainted_args = []
        for arg in call_node.args:
            if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                tainted_args.append(arg.id)
            elif isinstance(arg, ast.Call):
                temp_var = f"_temp_{arg.lineno}"
                if temp_var in self.tainted_vars:
                    tainted_args.append(temp_var)
        
        # 检查调用对象本身是否被污染（用于方法调用）
        if isinstance(call_node.func, ast.Attribute):
            if isinstance(call_node.func.value, ast.Name):
                obj_name = call_node.func.value.id
                if obj_name in self.tainted_vars:
                    print(f"  发现污染的对象: {obj_name}")
                    tainted_args.append(obj_name)
        
        # 先检查是否是传播器
        for propagator in self.propagators:
            spec_method = propagator.get("method", "")
            if spec_method and (spec_method == func_name or spec_method in full_call_chain):
                if tainted_args:
                    source_var = tainted_args[0]
                    self.tainted_vars[var_name] = self.tainted_vars[source_var].copy()
                    
                    for path in self.paths:
                        if path.nodes and path.nodes[-1].variable == source_var:
                            new_node = TaintNode("intermediate", self.file_path, lineno, 
                                               self.get_code_line(lineno))
                            new_node.variable = var_name
                            new_node.data = {"propagator": func_name, "from_var": source_var}
                            path.add_node(new_node)
                    return
        
        # 检查是否是源
        for source in self.sources:
            if source.get("llm_label") != "source":
                continue
            
            spec_method = source.get("method", "")
            
            if spec_method and spec_method in full_call_chain:
                self._mark_as_source(var_name, source, func_name, call_node, lineno)
                return
            
            if spec_method and spec_method == func_name:
                self._mark_as_source(var_name, source, func_name, call_node, lineno)
                return
    
    def _mark_as_source(self, var_name: str, source: Dict, func_name: str, call_node: ast.Call, lineno: int):
        self.tainted_vars[var_name].append({
            "line": lineno,
            "source": source,
            "func": func_name
        })
        
        path = TaintPath(source)
        node = TaintNode("source", self.file_path, lineno, self.get_code_line(lineno))
        node.variable = var_name
        node.data = {"source": source, "func": func_name}
        path.add_node(node)
        self.paths.append(path)
    
    def _check_sink(self, call_node: ast.Call, full_call_chain: str):
        if isinstance(call_node.func, ast.Name):
            func_name = call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            func_name = call_node.func.attr
        else:
            func_name = "unknown"
        
        for sink in self.sinks:
            if sink.get("llm_label") != "sink":
                continue
            
            spec_method = sink.get("method", "")
            
            if self._matches_api_by_llm(func_name, full_call_chain, sink):
                self._analyze_sink_parameters(call_node, sink, func_name)
                return
    
    def _matches_api_by_llm(self, func_name: str, full_call_chain: str, api_spec: Dict) -> bool:
        if not api_spec:
            return False
        
        spec_method = api_spec.get("method", "")
        
        if spec_method and spec_method in full_call_chain:
            return True
        
        if spec_method and spec_method == func_name:
            return True
        
        return False
    
    def _analyze_sink_parameters(self, call_node: ast.Call, sink: Dict, func_name: str):
        """分析汇的参数"""
        sink_args = sink.get("sink_args", [0])
        
        for arg_idx, arg in enumerate(call_node.args):
            is_dangerous_arg = arg_idx in sink_args or "this" in sink_args
            
            if not is_dangerous_arg:
                continue
            
            # 处理普通变量
            if isinstance(arg, ast.Name):
                var_name = arg.id
                if var_name in self.tainted_vars:
                    self._create_vulnerability_path(var_name, call_node, sink, arg_idx, func_name)
            
            # 处理属性访问
            elif isinstance(arg, ast.Attribute):
                if isinstance(arg.value, ast.Name):
                    obj_name = arg.value.id
                    if obj_name in self.tainted_vars:
                        # 对象的属性也被污染
                        self._create_vulnerability_path(obj_name, call_node, sink, arg_idx, func_name, is_attribute=True)
            
            # 处理 f-string
            elif isinstance(arg, ast.JoinedStr):
                for value in arg.values:
                    if isinstance(value, ast.FormattedValue):
                        if isinstance(value.value, ast.Name):
                            var_name = value.value.id
                            if var_name in self.tainted_vars:
                                self._create_vulnerability_path(
                                    var_name, call_node, sink, arg_idx, func_name, is_fstring=True
                                )
                        elif isinstance(value.value, ast.Attribute):
                            if isinstance(value.value.value, ast.Name):
                                obj_name = value.value.value.id
                                if obj_name in self.tainted_vars:
                                    self._create_vulnerability_path(
                                        obj_name, call_node, sink, arg_idx, func_name, is_fstring=True, is_attribute=True
                                    )
    
    def _create_vulnerability_path(self, var_name: str, call_node: ast.Call, 
                                   sink: Dict, arg_idx: int, func_name: str, 
                                   is_fstring: bool = False, is_attribute: bool = False):
        """创建漏洞路径"""
        for taint_info in self.tainted_vars[var_name]:
            source_info = taint_info.get("source", {})
            
            for path in self.paths:
                if path.source == source_info and path.sink is None:
                    if not path.nodes or path.nodes[-1].variable != var_name:
                        inter_node = TaintNode("intermediate", self.file_path, 
                                             call_node.lineno, 
                                             self.get_code_line(call_node.lineno))
                        inter_node.variable = var_name
                        inter_node.data = {
                            "propagation": True,
                            "is_attribute": is_attribute
                        }
                        path.add_node(inter_node)
                    
                    sink_node = TaintNode("sink", self.file_path, 
                                        call_node.lineno, 
                                        self.get_code_line(call_node.lineno))
                    sink_node.variable = var_name
                    sink_node.data = {
                        "sink": sink, 
                        "func": func_name, 
                        "arg_index": arg_idx,
                        "is_fstring": is_fstring,
                        "is_attribute": is_attribute
                    }
                    path.add_node(sink_node)
                    path.set_sink(sink)
                    return
    
    def get_paths(self) -> List[TaintPath]:
        return self.paths

    def visit_Attribute(self, node: ast.Attribute):
        """处理属性访问，如 obj.attr"""
        if isinstance(node.value, ast.Name):
            obj_name = node.value.id
            attr_name = node.attr
            if obj_name in self.tainted_vars:
                # 如果对象被污染，它的属性也被污染
                temp_var = f"{obj_name}.{attr_name}"
                # 注意：这里我们不直接创建新变量，而是在使用时检查
                print(f"  属性访问: {obj_name}.{attr_name} 继承污点")
        self.generic_visit(node)


class TaintAnalyzer:
    """污点分析引擎主类"""
    
    def __init__(self, project_files: Dict[str, str]):
        self.project_files = project_files
        self.sources: List[Dict] = []
        self.sinks: List[Dict] = []
        self.propagators: List[Dict] = []
        
    def set_sources(self, sources: List[Dict]):
        self.sources = [s for s in sources if s.get("llm_label") == "source" and s.get("llm_confidence", 0) >= 50]
        
    def set_sinks(self, sinks: List[Dict]):
        self.sinks = [s for s in sinks if s.get("llm_label") == "sink" and s.get("llm_confidence", 0) >= 50]
        
    def set_propagators(self, propagators: List[Dict]):
        self.propagators = [p for p in propagators if p.get("llm_confidence", 0) >= 50]
        
    def find_taint_paths(self, max_paths: int = 100) -> List[TaintPath]:
        all_paths = []
        
        for file_path, content in self.project_files.items():
            if not content:
                continue
            
            try:
                tree = ast.parse(content)
                tracker = TaintTracker(file_path, content, self.sources, self.sinks, self.propagators)
                tracker.visit(tree)
                
                paths = tracker.get_paths()
                if paths:
                    all_paths.extend(paths)
                    
            except SyntaxError:
                pass
            except Exception:
                pass
        
        complete_paths = [p for p in all_paths if p.sink is not None]
        return complete_paths[:max_paths]
