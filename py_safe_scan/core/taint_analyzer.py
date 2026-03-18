"""污点分析引擎 - 追踪从源到汇的数据流"""

import ast
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Any, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class TaintNode:
    """污点节点"""
    
    def __init__(self, node_type: str, file_path: str, line: int, code: str = ""):
        self.type = node_type  # 'source', 'sink', 'intermediate', 'call', 'param', 'variable'
        self.file = file_path
        self.line = line
        self.code = code
        self.data = {}  # 额外数据
        self.variable = None  # 变量名
        
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
        """添加节点"""
        self.nodes.append(node)
        
    def set_sink(self, sink: Dict):
        """设置汇"""
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
    """污点追踪器 - 遍历AST追踪变量传播"""
    
    def __init__(self, file_path: str, content: str, sources: List[Dict], sinks: List[Dict], propagators: List[Dict]):
        """污点追踪器初始化 - 注意这里有5个参数"""
        self.file_path = file_path
        self.content = content
        self.sources = sources
        self.sinks = sinks
        self.propagators = propagators  # 新增的传播器参数
        
        print(f"\n=== 初始化 TaintTracker ===")
        print(f"文件: {file_path}")
        print(f"源数量: {len(self.sources)}")
        for s in self.sources:
            print(f"  - {s.get('package')}.{s.get('method')} (置信度: {s.get('llm_confidence')})")
        print(f"汇数量: {len(self.sinks)}")
        for s in self.sinks:
            print(f"  - {s.get('package')}.{s.get('method')} (置信度: {s.get('llm_confidence')})")
        print(f"传播器数量: {len(self.propagators)}")
        for p in self.propagators:
            print(f"  - {p.get('package')}.{p.get('method')}")
        
        # 污点变量表 {变量名: [(行号, 来源信息)]}
        self.tainted_vars = defaultdict(list)
        
        # 发现的路径
        self.paths: List[TaintPath] = []
        
        # 当前函数
        self.current_function = None
        
        # 代码行缓存
        self.lines = content.split('\n')
        
    def get_code_line(self, lineno: int) -> str:
        """获取代码行"""
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno-1].strip()
        return ""
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """处理函数定义"""
        print(f"\n>>> 进入函数: {node.name} at 行 {node.lineno}")
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
        print(f"<<< 退出函数: {node.name}")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """处理异步函数定义"""
        self.visit_FunctionDef(node)
        
    def visit_Assign(self, node: ast.Assign):
        """处理赋值语句"""
        print(f"\n--- 处理赋值 at 行 {node.lineno} ---")
        try:
            print(f"代码: {ast.unparse(node)}")
        except:
            pass
        
        # 获取目标变量
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                print(f"目标变量: '{var_name}'")
                
                # 处理函数调用赋值
                if isinstance(node.value, ast.Call):
                    print(f"右侧是函数调用")
                    
                    # 在检查源之前，先检查参数中是否有源
                    self._check_call_arguments_for_sources(node.value)
                    
                    # 然后检查整个调用是否为源或传播器
                    self._check_call_source_or_propagator(var_name, node.value, node.lineno)
                    
                # 处理变量赋值
                elif isinstance(node.value, ast.Name):
                    right_var = node.value.id
                    print(f"右侧是变量: '{right_var}'")
                    
                    # 变量赋值传播污点
                    if right_var in self.tainted_vars:
                        print(f"✅ 污点传播: '{right_var}' -> '{var_name}'")
                        print(f"  污点来源: {self.tainted_vars[right_var]}")
                        self.tainted_vars[var_name] = self.tainted_vars[right_var].copy()
                        
                        # 添加到路径
                        for path in self.paths:
                            if path.nodes and path.nodes[-1].variable == right_var:
                                new_node = TaintNode("intermediate", self.file_path, node.lineno, 
                                                   self.get_code_line(node.lineno))
                                new_node.variable = var_name
                                new_node.data = {"from_var": right_var}
                                path.add_node(new_node)
                                print(f"  已添加到路径")
                    else:
                        print(f"❌ 变量 '{right_var}' 未被污染")
        
        self.generic_visit(node)
    
    def _check_call_arguments_for_sources(self, call_node: ast.Call):
        """检查函数调用的参数中是否有源"""
        for arg in call_node.args:
            if isinstance(arg, ast.Call):
                # 嵌套调用
                self._check_call_arguments_for_sources(arg)
                
                # 检查这个嵌套调用本身是否为源
                if isinstance(arg.func, ast.Name):
                    inner_func = arg.func.id
                elif isinstance(arg.func, ast.Attribute):
                    inner_func = arg.func.attr
                else:
                    continue
                
                # 创建一个临时变量名来存储结果
                temp_var = f"_temp_{arg.lineno}"
                print(f"  检查嵌套调用: {inner_func}，临时变量: {temp_var}")
                self._check_call_source_or_propagator(temp_var, arg, arg.lineno)
    
    def visit_AugAssign(self, node: ast.AugAssign):
        """处理增强赋值 (+=, -= 等)"""
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            print(f"\n--- 处理增强赋值 at 行 {node.lineno}: {var_name} {type(node.op).__name__}= ...")
            if var_name in self.tainted_vars:
                print(f"  变量 '{var_name}' 保持污点")
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """处理函数调用"""
        # 获取完整调用链
        full_call_chain = self._get_full_call_chain(node)
        
        # 获取函数名
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        else:
            func_name = "unknown"
        
        print(f"\n--- 处理函数调用 at 行 {node.lineno}: {func_name} ---")
        print(f"完整调用链: {full_call_chain}")
        
        # 显示参数
        for i, arg in enumerate(node.args):
            if isinstance(arg, ast.Name):
                print(f"  参数{i}: 变量 '{arg.id}'")
            elif isinstance(arg, ast.Constant):
                print(f"  参数{i}: 常量 {arg.value}")
            elif isinstance(arg, ast.JoinedStr):
                print(f"  参数{i}: f-string")
        
        # 检查是否是汇（敏感操作）
        self._check_sink(node, full_call_chain)
        
        self.generic_visit(node)
    
    def visit_JoinedStr(self, node: ast.JoinedStr):
        """处理 f-string"""
        print(f"\n--- 处理 f-string at 行 {node.lineno} ---")
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if isinstance(value.value, ast.Name):
                    var_name = value.value.id
                    print(f"  f-string 中包含变量: '{var_name}'")
                    if var_name in self.tainted_vars:
                        print(f"  ✅ 污点变量在 f-string 中: {var_name}")
                        # 添加到路径
                        for path in self.paths:
                            if path.nodes and path.nodes[-1].variable == var_name:
                                new_node = TaintNode("intermediate", self.file_path, node.lineno,
                                                   self.get_code_line(node.lineno))
                                new_node.variable = var_name
                                new_node.data = {"in_fstring": True}
                                path.add_node(new_node)
        self.generic_visit(node)
    
    def _get_full_call_chain(self, call_node: ast.Call) -> str:
        """获取完整的调用链（如 'request.cookies.get'）"""
        try:
            return ast.unparse(call_node.func)
        except:
            return ""
    
    def _check_call_source_or_propagator(self, var_name: str, call_node: ast.Call, lineno: int):
        """检查函数调用是否为源或传播器"""
        print(f"\n  --- 检查源/传播器: {var_name} = ... 行 {lineno} ---")
        
        # 获取完整的调用链
        full_call_chain = self._get_full_call_chain(call_node)
        print(f"  完整调用链: {full_call_chain}")
        
        # 获取函数名
        if isinstance(call_node.func, ast.Name):
            func_name = call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            func_name = call_node.func.attr
        else:
            func_name = "unknown"
        
        print(f"  函数名: {func_name}")
        
        # 先检查参数中是否有污点变量（用于传播器）
        tainted_args = []
        for arg in call_node.args:
            if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                tainted_args.append(arg.id)
                print(f"  发现污点参数: {arg.id}")
            elif isinstance(arg, ast.Call):
                # 嵌套调用，需要检查其返回值是否被污染
                temp_var = f"_temp_{arg.lineno}"
                if temp_var in self.tainted_vars:
                    tainted_args.append(temp_var)
                    print(f"  发现污点来自嵌套调用: {temp_var}")
        
        # 如果是传播器且有污点参数，传播污点
        for propagator in self.propagators:
            spec_method = propagator.get("method", "")
            if spec_method and (spec_method == func_name or spec_method in full_call_chain):
                if tainted_args:
                    print(f"  ✅ 传播器 {func_name} 传播污点")
                    # 将第一个污点参数传播给返回值
                    source_var = tainted_args[0]
                    self.tainted_vars[var_name] = self.tainted_vars[source_var].copy()
                    print(f"  污点从 {source_var} 传播到 {var_name}")
                    
                    # 添加到路径
                    for path in self.paths:
                        if path.nodes and path.nodes[-1].variable == source_var:
                            new_node = TaintNode("intermediate", self.file_path, lineno, 
                                               self.get_code_line(lineno))
                            new_node.variable = var_name
                            new_node.data = {"propagator": func_name, "from_var": source_var}
                            path.add_node(new_node)
                            print(f"  已通过传播器添加到路径")
                    return
                else:
                    print(f"  传播器 {func_name} 但没有污点参数")
        
        # 如果不是传播器，继续检查是否为源
        print(f"  检查是否为源...")
        for source in self.sources:
            if source.get("llm_label") != "source":
                continue
            
            spec_method = source.get("method", "")
            print(f"    比较: {func_name} vs {spec_method}")
            
            # 检查完整调用链是否匹配
            if spec_method and spec_method in full_call_chain:
                print(f"  ✅ 方法名在调用链中找到!")
                self._mark_as_source(var_name, source, func_name, call_node, lineno)
                return
            
            # 方法名匹配
            if spec_method and spec_method == func_name:
                print(f"  ✅ 方法名匹配成功!")
                self._mark_as_source(var_name, source, func_name, call_node, lineno)
                return
    
    def _mark_as_source(self, var_name: str, source: Dict, func_name: str, call_node: ast.Call, lineno: int):
        """将变量标记为源"""
        print(f"  ✅ 发现源: {func_name} -> {var_name}")
        self.tainted_vars[var_name].append({
            "line": lineno,
            "source": source,
            "func": func_name
        })
        
        # 创建新路径
        path = TaintPath(source)
        node = TaintNode("source", self.file_path, lineno, self.get_code_line(lineno))
        node.variable = var_name
        node.data = {"source": source, "func": func_name}
        path.add_node(node)
        self.paths.append(path)
        print(f"  当前路径数: {len(self.paths)}")
    
    def _check_sink(self, call_node: ast.Call, full_call_chain: str):
        """检查是否为汇 - 完全依赖LLM标记"""
        # 获取函数名
        if isinstance(call_node.func, ast.Name):
            func_name = call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            func_name = call_node.func.attr
        else:
            func_name = "unknown"
        
        print(f"\n  --- 检查汇: {func_name} ---")
        
        # 遍历LLM标记的汇
        for sink in self.sinks:
            if sink.get("llm_label") != "sink":
                continue
            
            spec_method = sink.get("method", "")
            print(f"    比较: {func_name} vs {spec_method}")
            
            if self._matches_api_by_llm(func_name, full_call_chain, sink):
                print(f"  ✅ 匹配到汇: {func_name}")
                self._analyze_sink_parameters(call_node, sink, func_name)
                return
    
    def _matches_api_by_llm(self, func_name: str, full_call_chain: str, api_spec: Dict) -> bool:
        """根据LLM的标记匹配API"""
        if not api_spec:
            return False
        
        # 获取API规范中的方法名
        spec_method = api_spec.get("method", "")
        
        # 检查方法名是否在完整调用链中
        if spec_method and spec_method in full_call_chain:
            print(f"      ✅ 方法名在调用链中")
            return True
        
        # 检查方法名匹配
        if spec_method and spec_method == func_name:
            print(f"      ✅ 方法名匹配")
            return True
        
        print(f"      ❌ 不匹配")
        return False
    
    def _analyze_sink_parameters(self, call_node: ast.Call, sink: Dict, func_name: str):
        """分析汇的参数"""
        print(f"\n    --- 分析汇参数 ---")
        
        sink_args = sink.get("sink_args", [0])  # 默认第一个参数
        print(f"    危险参数索引: {sink_args}")
        
        for arg_idx, arg in enumerate(call_node.args):
            print(f"\n    检查参数 {arg_idx}:")
            
            # 检查这个参数是否被标记为危险
            is_dangerous_arg = arg_idx in sink_args or "this" in sink_args
            
            if not is_dangerous_arg:
                print(f"      参数 {arg_idx} 不是危险参数")
                continue
            
            print(f"      参数 {arg_idx} 是危险参数")
            
            # 处理普通变量
            if isinstance(arg, ast.Name):
                var_name = arg.id
                print(f"      变量名: '{var_name}'")
                
                if var_name in self.tainted_vars:
                    print(f"      ✅ 变量 '{var_name}' 被污染!")
                    self._create_vulnerability_path(var_name, call_node, sink, arg_idx, func_name)
                else:
                    print(f"      ❌ 变量 '{var_name}' 未被污染")
            
            # 处理 f-string
            elif isinstance(arg, ast.JoinedStr):
                print(f"      参数是 f-string")
                for value in arg.values:
                    if (isinstance(value, ast.FormattedValue) and 
                        isinstance(value.value, ast.Name) and 
                        value.value.id in self.tainted_vars):
                        var_name = value.value.id
                        print(f"      ✅ f-string 中包含污染变量 '{var_name}'")
                        self._create_vulnerability_path(
                            var_name, call_node, sink, arg_idx, func_name, is_fstring=True
                        )
    
    def _create_vulnerability_path(self, var_name: str, call_node: ast.Call, 
                                   sink: Dict, arg_idx: int, func_name: str, 
                                   is_fstring: bool = False):
        """创建漏洞路径"""
        print(f"\n        --- 创建漏洞路径 for '{var_name}' ---")
        
        for taint_info in self.tainted_vars[var_name]:
            source_info = taint_info.get("source", {})
            print(f"        源信息: {source_info.get('method')}")
            
            # 查找对应的源路径
            for path in self.paths:
                if path.source == source_info and path.sink is None:
                    print(f"        找到匹配的路径")
                    
                    # 添加中间节点（如果还没有）
                    if not path.nodes or path.nodes[-1].variable != var_name:
                        inter_node = TaintNode("intermediate", self.file_path, 
                                             call_node.lineno, 
                                             self.get_code_line(call_node.lineno))
                        inter_node.variable = var_name
                        inter_node.data = {"propagation": True}
                        path.add_node(inter_node)
                        print(f"        添加中间节点")
                    
                    # 添加汇节点
                    sink_node = TaintNode("sink", self.file_path, 
                                        call_node.lineno, 
                                        self.get_code_line(call_node.lineno))
                    sink_node.variable = var_name
                    sink_node.data = {
                        "sink": sink, 
                        "func": func_name, 
                        "arg_index": arg_idx,
                        "is_fstring": is_fstring
                    }
                    path.add_node(sink_node)
                    path.set_sink(sink)
                    
                    print(f"        ✅ 发现漏洞: {var_name} 从源到汇 {func_name} 在行 {call_node.lineno}")
                    return
        
        print(f"        ❌ 没有找到匹配的源路径")
    
    def get_paths(self) -> List[TaintPath]:
        """获取发现的路径"""
        print(f"\n=== 追踪完成 ===")
        print(f"污点变量: {list(self.tainted_vars.keys())}")
        print(f"路径数: {len(self.paths)}")
        for i, path in enumerate(self.paths):
            print(f"路径 {i+1}: 源={path.source.get('method')}, 节点数={len(path.nodes)}")
            if path.sink:
                print(f"  已找到汇: {path.sink.get('method')}")
            else:
                print(f"  未找到汇")
        return self.paths


class TaintAnalyzer:
    """污点分析引擎主类"""
    
    def __init__(self, project_files: Dict[str, str]):
        """
        初始化污点分析引擎
        
        Args:
            project_files: 项目文件映射 {file_path: file_content}
        """
        self.project_files = project_files
        self.sources: List[Dict] = []
        self.sinks: List[Dict] = []
        self.propagators: List[Dict] = []  # 添加这一行
        
    def set_sources(self, sources: List[Dict]):
        """设置源 - 只保留LLM标记为source的"""
        self.sources = [s for s in sources if s.get("llm_label") == "source" and s.get("llm_confidence", 0) >= 50]
        print(f"\n设置 {len(self.sources)} 个源 (置信度>=50):")
        for s in self.sources:
            print(f"  - {s.get('package')}.{s.get('method')}")
        
    def set_sinks(self, sinks: List[Dict]):
        """设置汇 - 只保留LLM标记为sink的"""
        self.sinks = [s for s in sinks if s.get("llm_label") == "sink" and s.get("llm_confidence", 0) >= 50]
        print(f"设置 {len(self.sinks)} 个汇 (置信度>=50):")
        for s in self.sinks:
            print(f"  - {s.get('package')}.{s.get('method')}")

    def set_propagators(self, propagators: List[Dict]):
        """设置传播器"""
        self.propagators = [p for p in propagators if p.get("llm_confidence", 0) >= 50]
        print(f"设置 {len(self.propagators)} 个传播器 (置信度>=50):")
        for p in self.propagators:
            print(f"  - {p.get('package')}.{p.get('method')}")
        
    def find_taint_paths(self, max_paths: int = 100) -> List[TaintPath]:
        """
        查找所有从源到汇的污点路径
        
        Returns:
            污点路径列表
        """
        all_paths = []
        
        print(f"\n{'='*70}")
        print(f"开始污点分析，共 {len(self.project_files)} 个文件")
        print(f"{'='*70}")
        
        # 对每个文件进行分析
        for file_path, content in self.project_files.items():
            if not content:
                continue
            
            print(f"\n分析文件: {file_path}")
            print("-" * 50)
            
            try:
                tree = ast.parse(content)
                # 传入5个参数：file_path, content, sources, sinks, propagators
                tracker = TaintTracker(file_path, content, self.sources, self.sinks, self.propagators)
                tracker.visit(tree)
                
                paths = tracker.get_paths()
                if paths:
                    print(f"在文件中发现 {len(paths)} 条路径")
                    all_paths.extend(paths)
                else:
                    print(f"文件中没有发现路径")
                    
            except SyntaxError as e:
                print(f"语法错误: {e}")
            except Exception as e:
                print(f"分析失败: {e}")
        
        # 过滤出完整的路径（既有源又有汇）
        complete_paths = [p for p in all_paths if p.sink is not None]
        
        print(f"\n{'='*70}")
        print(f"分析完成: 共发现 {len(complete_paths)} 条完整污点路径")
        print(f"{'='*70}")
        
        return complete_paths[:max_paths]
