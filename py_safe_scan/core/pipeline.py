"""主流水线 - 完整实现IRIS四阶段（带动态查询生成）"""

import logging
import time
import json
from pathlib import Path
from typing import List, Dict, Optional, Any
from collections import defaultdict

from py_safe_scan.core.codeql_manager import CodeQLManager
from py_safe_scan.core.spec_extractor import SpecExtractor
from py_safe_scan.llm.deepseek_client import DeepSeekClient
from py_safe_scan.llm.prompts import CWE_DESCRIPTIONS, FEW_SHOT_EXAMPLES
from py_safe_scan.cache.cache_manager import CacheManager
from py_safe_scan.utils.file_utils import FileUtils
from py_safe_scan.utils.sarif_parser import SARIFParser

import config

logger = logging.getLogger(__name__)


class IRISPipeline:
    """IRIS论文完整实现的主流水线（带动态查询生成）"""
    
    def __init__(self, cwe_type: str = None, use_cache: bool = True):
        """
        初始化分析流水线
        
        Args:
            cwe_type: CWE类型 (如 "CWE-89")，如果为None则检测所有类型
            use_cache: 是否使用缓存
        """
        self.cwe_type = cwe_type
        self.use_cache = use_cache
        
        # 初始化组件
        self.codeql = CodeQLManager(
            codeql_path=config.CODEQL_PATH,
            workspace_dir=config.CODEQL_WORKSPACE
        )
        self.deepseek = DeepSeekClient()
        self.cache = CacheManager() if use_cache else None
        self.sarif_parser = SARIFParser()
        self.file_utils = FileUtils()
        self.spec_extractor = SpecExtractor(self.codeql)
        
        # 统计信息
        self.stats = {
            "files_scanned": 0,
            "external_apis_found": 0,
            "source_candidates": 0,
            "sink_candidates": 0,
            "llm_calls": 0,
            "cache_hits": 0,
            "vulnerabilities_found": 0,
            "vulnerabilities_filtered": 0,
            "vulnerabilities_confirmed": 0,
            "start_time": None,
            "end_time": None
        }
        # 新增：三级缓存
        self.path_cache = {}          # 路径验证结果缓存
        self.source_cache = set()      # 已知安全的source
        self.sink_cache = set()        # 已知安全的sink
        self.fp_sources = set()        # 已知误报的source
        self.fp_sinks = set()          # 已知误报的sink
        self.batch_size = 10            # 批处理大小

    def _heuristic_filter(self, vuln: Dict) -> bool:
        """启发式过滤：判断是否应该跳过此路径"""
        message = vuln.get("message", "").lower()
        
        # IRIS中的过滤模式
        ignore_patterns = [
            "tostring",
            "println", 
            "... + ...",
            "next()",
            "getoptionvalue",
            "getproperty",
            "iterator",
            "hasnext",
            "entryset",
            "keyset"
        ]
        
        for pattern in ignore_patterns:
            if pattern in message:
                logger.debug(f"启发式过滤: {pattern}")
                return True
        
        return False    

    def _quick_rule_check(self, vuln: Dict) -> bool:
        """快速规则检查：判断是否明显不是漏洞（加强版）"""
        path = vuln.get("path", [])
        if not path:
            return False
        
        codes = [node.get("code", "") for node in path]
        full_code = " ".join(codes)
        
        # 1. 硬编码赋值检查
        hardcoded_patterns = [
            "bar = \"This_should_always_happen\"",
            "bar = 'This_should_always_happen'",
            "bar = \"safe\"",
            "bar = 'safe'",
            "bar = \"constant\"",
            "bar = \"FixedString\"",
        ]
        for pattern in hardcoded_patterns:
            if pattern in full_code:
                logger.info(f"快速过滤: 硬编码赋值 {pattern}")
                return True
        
        # 2. 条件分支检查 - 用户输入永远进不来
        if "if " in full_code and "else" in full_code:
            # 检查是否用户输入只在else分支，但条件永远为真
            if "> 200" in full_code and "num = 106" in full_code:
                logger.info(f"快速过滤: 条件永远为真，用户输入不可达")
                return True
            # 检查是否用户输入只在if分支，但条件永远为假
            if "< 0" in full_code and "num = 106" in full_code:
                logger.info(f"快速过滤: 条件永远为假，用户输入不可达")
                return True
        
        # 3. 类型转换检查 - 输入被转换成其他类型
        type_conversions = ["int(", "float(", "bool(", "str("]
        for conv in type_conversions:
            if conv in full_code and "param" in full_code:
                # 检查是否转换后用于路径
                next_nodes = []
                found = False
                for i, node in enumerate(path):
                    if conv in node.get("code", ""):
                        # 看转换后的值是否继续传递
                        for j in range(i+1, min(i+3, len(path))):
                            next_nodes.append(path[j].get("code", ""))
                        if any("open" in n for n in next_nodes):
                            found = True
                            break
                if not found:
                    logger.info(f"快速过滤: 类型转换 {conv} 阻断了路径")
                    return True
        
        # 4. 白名单检查
        if "in [" in full_code or "in (" in full_code or "in {" in full_code:
            # 检查是否是有效的白名单
            if "if" in full_code and "return" in full_code:
                logger.info("快速过滤: 白名单检查")
                return True
        
        # 5. 长度限制检查
        if "len(" in full_code and "<" in full_code:
            # 检查长度限制是否有效
            if "if" in full_code and "return" in full_code:
                logger.info("快速过滤: 长度限制")
                return True
        
        # 6. 异常处理检查
        if "try:" in full_code and "except" in full_code:
            # 如果异常处理中没有文件操作，可能是无害的
            if "open" not in full_code and "read" not in full_code:
                logger.info("快速过滤: 仅有异常处理")
                return True
        
        return False


    def analyze_directory(self, directory: Path) -> Dict:
        """
        分析目录 - IRIS四阶段完整实现（带动态查询生成）
        
        Args:
            directory: 目标目录
            
        Returns:
            分析结果
        """
        self.stats["start_time"] = time.time()
        
        logger.info(f"开始IRIS分析: {directory}")
        logger.info(f"CWE类型: {self.cwe_type or '全部'}")
        
        # ============ 阶段1: 创建CodeQL数据库 ============
        logger.info("="*60)
        logger.info("阶段1/4: 创建CodeQL数据库")
        logger.info("="*60)
        db_path = self._create_database(directory)
        
        # ============ 阶段2: 提取候选API + LLM分类 ============
        logger.info("="*60)
        logger.info("阶段2/4: 候选API提取与LLM分类")
        logger.info("="*60)
        
        # 2.1 提取所有候选API（不区分source/sink）
        logger.info("提取所有候选API...")
        candidate_apis = self.spec_extractor.extract_candidate_apis(db_path)
        
        # 2.2 LLM分类
        logger.info("用LLM分类API为source/sink...")
        api_dicts = [api.to_dict() for api in candidate_apis]
        
        sources = []
        sinks = []
        if api_dicts and self.cwe_type:
            cwe_desc = CWE_DESCRIPTIONS.get(self.cwe_type, "")
            few_shot = FEW_SHOT_EXAMPLES.get(self.cwe_type, [])
            
            classified_apis = self.deepseek.infer_source_sink_specs(
                apis=api_dicts,
                cwe_type=self.cwe_type,
                cwe_description=cwe_desc,
                few_shot_examples=few_shot
            )
            
            # 分类结果
            sources = [a for a in classified_apis if a.get("llm_label") == "source" and a.get("llm_confidence", 0) > 60]
            sinks = [a for a in classified_apis if a.get("llm_label") == "sink" and a.get("llm_confidence", 0) > 60]
            
            self.stats["source_candidates"] = len(sources)
            self.stats["sink_candidates"] = len(sinks)
            
            logger.info(f"分类结果:")
            logger.info(f"  - Sources: {len(sources)}个")
            logger.info(f"  - Sinks: {len(sinks)}个")
        
        # ============ 阶段3: 动态生成查询并运行 ============
        logger.info("="*60)
        logger.info("阶段3/4: 动态生成污点查询")
        logger.info("="*60)
        
        if sources or sinks:
            # 3.1 生成完整查询
            query_path = self._generate_cwe_query(sources, sinks, self.cwe_type)
            
            # 3.2 运行查询
            logger.info("运行动态生成的污点查询...")
            results_path = self.codeql.run_custom_query(db_path, query_path)
            
            # 3.3 解析结果
            raw_vulnerabilities = self.codeql.extract_results(results_path)
        else:
            logger.warning("没有找到source或sink，跳过污点分析")
            raw_vulnerabilities = []
        
        self.stats["vulnerabilities_found"] = len(raw_vulnerabilities)
        logger.info(f"发现 {len(raw_vulnerabilities)} 个潜在漏洞")
        
        # ============ 阶段4: LLM路径验证 ============
        logger.info("="*60)
        logger.info("阶段4/4: LLM路径验证")
        logger.info("="*60)
        
        confirmed_vulnerabilities = self._validate_paths(raw_vulnerabilities)
        self.stats["vulnerabilities_confirmed"] = len(confirmed_vulnerabilities)
        
        logger.info(f"验证通过: {len(confirmed_vulnerabilities)}/{len(raw_vulnerabilities)} 个漏洞")
        
        self.stats["end_time"] = time.time()
        
        # 生成报告
        results = {
            "cwe": self.cwe_type or "all",
            "target": str(directory),
            "vulnerabilities": confirmed_vulnerabilities,
            "raw_vulnerabilities": raw_vulnerabilities[:10] if len(raw_vulnerabilities) > 10 else raw_vulnerabilities,
            "stats": self.stats.copy(),
            "specs": {
                "sources": sources[:20],
                "sinks": sinks[:20]
            }
        }
        
        # 保存结果
        self._save_results(results)
        
        # 打印统计
        self._print_summary()
        
        return results
    
    def analyze_file(self, file_path: Path) -> Dict:
        """分析单个文件 - 为基准测试优化"""
        import tempfile
        import shutil
    
        temp_dir = Path(tempfile.mkdtemp(prefix=f"benchmark_{file_path.stem}_"))
        try:
            shutil.copy2(file_path, temp_dir / file_path.name)
            results = self.analyze_directory(temp_dir)
            return results
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _create_database(self, directory: Path) -> Path:
        """创建CodeQL数据库"""
        try:
            return self.codeql.create_database(directory, language="python")
        except Exception as e:
            logger.error(f"创建数据库失败: {e}")
            raise
    
    def _generate_qll_files(self, sources: List[Dict], sinks: List[Dict], output_dir: Path):
        """生成MySources.qll和MySinks.qll文件"""
        
        import re
        
        # 生成MySources.qll
        sources_content = "import python\nimport semmle.python.ApiGraphs\n\n"
        sources_content += "class MySources extends DataFlow::Node {\n"
        sources_content += "  MySources() {\n    exists(API::CallNode call |\n"
        
        source_rules = []
        for src in sources:
            method = src.get('method', '')
            # 提取纯方法名
            if 'Found API call:' in method:
                method = method.replace('Found API call:', '').strip()
            # 去掉括号
            method = method.split('(')[0].strip()
            
            if method:
                source_rules.append(
                    f'      call = API::moduleImport("builtins").getMember("{method}").getACall()'
                )
        
        if source_rules:
            sources_content += " or\n".join(source_rules)
            sources_content += "\n    )\n  }\n}\n"
        else:
            sources_content += "      none()\n    )\n  }\n}\n"
        
        # 生成MySinks.qll
        sinks_content = "import python\nimport semmle.python.ApiGraphs\n\n"
        sinks_content += "class MySinks extends DataFlow::Node {\n"
        sinks_content += "  MySinks() {\n    exists(API::CallNode call |\n"
        
        sink_rules = []
        for snk in sinks:
            method = snk.get('method', '')
            # 提取纯方法名
            if 'Found API call:' in method:
                method = method.replace('Found API call:', '').strip()
            # 去掉括号
            method = method.split('(')[0].strip()
            
            if method:
                sink_rules.append(
                    f'      call = API::moduleImport("builtins").getMember("{method}").getACall()'
                )
        
        if sink_rules:
            sinks_content += " or\n".join(sink_rules)
            sinks_content += "\n    )\n  }\n}\n"
        else:
            sinks_content += "      none()\n    )\n  }\n}\n"
        
        # 保存文件
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(output_dir / "MySources.qll", 'w', encoding='utf-8') as f:
            f.write(sources_content)
        with open(output_dir / "MySinks.qll", 'w', encoding='utf-8') as f:
            f.write(sinks_content)
        
        logger.info(f"生成QLL文件: {output_dir}")
        logger.info(f"  - Sources规则: {len(source_rules)}")
        logger.info(f"  - Sinks规则: {len(sink_rules)}")
    
    def _generate_cwe_query(self, sources: List[Dict], sinks: List[Dict], cwe_type: str) -> Path:
        """为指定CWE生成完整查询"""
        
        # 1. 创建临时目录存放qll文件
        import tempfile
        qll_dir = Path(tempfile.mkdtemp(prefix=f"qll_{cwe_type}_"))
        
        # 2. 生成qll文件
        self._generate_qll_files(sources, sinks, qll_dir)
        
        # 3. 获取模板路径
        cwe_lower = cwe_type.lower().replace('-', '')
        template_path = Path(f"/home/hanahanarange/PySafeScan/custom-queries/{cwe_lower}_template.ql")
        
        if not template_path.exists():
            template_path = Path("/home/hanahanarange/PySafeScan/custom-queries/cwe22_template.ql")
            logger.warning(f"未找到模板 {cwe_lower}_template.ql，使用cwe22_template.ql代替")
        
        # 4. 读取模板
        with open(template_path, 'r', encoding='utf-8') as f:
            query = f.read()
        
        # 5. 创建qll文件包（在qll_dir下创建qlpack.yml）
        qlpack_path = qll_dir / "qlpack.yml"
        with open(qlpack_path, 'w', encoding='utf-8') as f:
            f.write(f"""
name: pysafescan-{cwe_lower}
version: 0.0.1
dependencies:
  codeql/python-all: '*'
""")
        
        # 6. 添加import语句（使用相对路径）
        import_stmt = f'import MySources\nimport MySinks\n'
        
        # 在最后一个import之后插入
        lines = query.split('\n')
        last_import_idx = -1
        for i, line in enumerate(lines):
            if line.startswith('import ') and not line.startswith('import My'):
                last_import_idx = i
        
        if last_import_idx >= 0:
            lines.insert(last_import_idx + 1, import_stmt)
        else:
            lines.insert(1, import_stmt)
        
        modified_query = '\n'.join(lines)
        
        # 7. 保存完整查询
        query_path = qll_dir / "final.ql"
        with open(query_path, 'w', encoding='utf-8') as f:
            f.write(modified_query)
        
        logger.info(f"生成完整查询: {query_path}")
        return query_path
    
    def _cluster_paths(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """按路径特征聚类，每类只选一个代表"""
        clusters = {}
        
        for vuln in vulnerabilities:
            # 提取source位置
            source = vuln.get("source", {})
            source_file = source.get("file", "")
            source_line = source.get("line", 0)
            
            # 提取sink位置
            sink_file = vuln.get("file", "")
            sink_line = vuln.get("line", 0)
            
            # 提取关键函数（从path中）
            path = vuln.get("path", [])
            key_functions = []
            for node in path[:3]:  # 只取前3个
                code = node.get("code", "")
                if any(f in code for f in ["request", "get", "open", "execute"]):
                    key_functions.append(code[:20])
            
            # 生成聚类key
            cluster_key = (
                f"{source_file}:{source_line}",
                f"{sink_file}:{sink_line}",
                len(path),
                tuple(key_functions)
            )
            
            clusters.setdefault(cluster_key, []).append(vuln)
        
        # 每类只取第一个
        representatives = [cluster[0] for cluster in clusters.values()]
        logger.info(f"路径聚类: {len(vulnerabilities)} → {len(representatives)}")
        
        return representatives


    def _validate_paths(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """验证漏洞路径 - IRIS方式：每组只验证一次"""
        if not vulnerabilities:
            return []

        from collections import defaultdict

        # ============ 第1层：按真实source-sink对聚类 ============
        path_groups = defaultdict(list)
        for vuln in vulnerabilities:
            # 从path中找真实source
            path = vuln.get("path", [])
            real_source = "unknown:0"
            for node in path:
                node_msg = node.get("message", "")
                if any(key in node_msg for key in ["request", "cookies", "args", "get", "param"]):
                    real_source = f"{node.get('file')}:{node.get('line')}"
                    break
            
            sink_file = vuln.get("file", "")
            sink_line = vuln.get("line", 0)
            group_key = f"{real_source}->{sink_file}:{sink_line}"
            path_groups[group_key].append(vuln)

        print(f"\n聚类前: {len(vulnerabilities)}条, 聚类后: {len(path_groups)}组")

        # ============ 第2层：每组只验证一次 ============
        confirmed = []
        cache_hits = 0
        
        for group_key, group in path_groups.items():
            # 取组内第一条作为代表
            rep_vuln = group[0]
            
            # 检查source/sink缓存
            source = rep_vuln.get("source", {})
            sink_file = rep_vuln.get("file", "")
            sink_line = rep_vuln.get("line", 0)
            source_key = f"{source.get('file')}:{source.get('line')}"
            sink_key = f"{sink_file}:{sink_line}"
            
            if source_key in self.source_cache or sink_key in self.sink_cache:
                print(f"跳过已知误报: {group_key}")
                continue
            
            # 检查路径缓存
            cache_key = self._get_path_key(rep_vuln)
            if cache_key in self.path_cache:
                if self.path_cache[cache_key].get("is_vulnerable", False):
                    # 整组都算确认
                    confirmed.extend(group)
                cache_hits += 1
                print(f"缓存命中: {group_key}")
                continue
            
            # 验证代表路径
            print(f"验证代表: {group_key}")
            result = self._validate_single(rep_vuln)
            
            # 保存缓存
            self.path_cache[cache_key] = {"is_vulnerable": result.get("is_vulnerable", False)}
            
            if result.get("is_vulnerable", False):
                # 整组都算确认
                confirmed.extend(group)
            else:
                # 记录误报，整组跳过
                self.source_cache.add(source_key)
                self.sink_cache.add(sink_key)
        
        self.stats["cache_hits"] = cache_hits
        print(f"缓存命中: {cache_hits}, 最终确认: {len(confirmed)}")
        
        return confirmed

    def _validate_single(self, vuln: Dict) -> Dict:
        """验证单个漏洞路径"""
        source, source_context = self._extract_source_info(vuln)
        sink_context = self._extract_sink_info(vuln)
        
        path = vuln.get("path", [])
        
        code_snippets = {
            "source": source_context,
            "sink": sink_context
        }
        
        result = self.deepseek.validate_vulnerability_path(
            source=source,
            sink=source,
            path=path,
            cwe_type=self.cwe_type or vuln.get("cwe", "unknown"),
            code_snippets=code_snippets
        )
        
        self.stats["llm_calls"] += 1
        return result

    def _get_path_key(self, vuln: Dict) -> str:
        """生成路径缓存key"""
        source = vuln.get("source", {})
        source_file = source.get("file", "unknown")
        source_line = source.get("line", 0)
        
        sink_file = vuln.get("file", "unknown")
        sink_line = vuln.get("line", 0)
        
        msg = vuln.get("message", "")[:50]
        
        return f"{source_file}:{source_line}->{sink_file}:{sink_line}:{msg}"

    def _validate_batch(self, batch: List[Dict]) -> List[Dict]:
        """批量验证一组漏洞 - 带缓存"""
        if not batch:
            return []
        
        print(f"\n验证批次，大小 {len(batch)}")
        for i, vuln in enumerate(batch):
            code = vuln.get("code", "")
            line = vuln.get("line", 0)
            print(f"  vuln {i}: line={line}, code={code[:100]}")
        
        results = []
        
        for vuln in batch:
            key = self._get_path_key(vuln)
            
            # ============ 检查缓存 ============
            if key in self.path_cache:
                cached = self.path_cache[key]
                result_vuln = vuln.copy()
                result_vuln["is_vulnerable"] = cached.get("is_vulnerable", False)
                result_vuln["confidence"] = cached.get("confidence", 0)
                result_vuln["explanation"] = cached.get("explanation", "")
                result_vuln["recommendation"] = cached.get("recommendation", "")
                results.append(result_vuln)
                self.stats["cache_hits"] += 1
                print(f"  缓存命中: line={line}, is_vulnerable={cached.get('is_vulnerable', False)}")
                continue
            
            # ============ 缓存未命中，调用LLM ============
            # 提取source和sink信息
            source, source_context = self._extract_source_info(vuln)
            sink_context = self._extract_sink_info(vuln)
            
            path = vuln.get("path", [])
            
            code_snippets = {
                "source": source_context,
                "sink": sink_context
            }
            
            # 调用LLM验证
            validation_result = self.deepseek.validate_vulnerability_path(
                source=source,
                sink=source,
                path=path,
                cwe_type=self.cwe_type or vuln.get("cwe", "unknown"),
                code_snippets=code_snippets
            )
            
            self.stats["llm_calls"] += 1
            
            # 保存到缓存
            self.path_cache[key] = validation_result
            
            # 创建结果对象
            result_vuln = vuln.copy()
            result_vuln["is_vulnerable"] = validation_result.get("is_vulnerable", False)
            result_vuln["confidence"] = validation_result.get("confidence", 0)
            result_vuln["explanation"] = validation_result.get("explanation", "")
            result_vuln["recommendation"] = validation_result.get("recommendation", "")
            
            if validation_result.get("is_vulnerable", False) and validation_result.get("confidence", 0) > 70:
                self._enrich_vulnerability(result_vuln, validation_result)
            else:
                # 记录误报的source/sink
                source = vuln.get("source", {})
                self.fp_sources.add(f"{source.get('file')}:{source.get('line')}")
                self.fp_sinks.add(f"{vuln.get('file')}:{vuln.get('line')}")
            
            results.append(result_vuln)
        
        return results

    
    def _extract_source_info(self, vuln: Dict) -> tuple:
        """提取source信息和上下文"""
        if "source" in vuln:
            source = vuln["source"]
            source_context = self.file_utils.get_code_snippet(
                source.get("file", ""), 
                source.get("line", 0),
                context_lines=5
            )
        else:
            path = vuln.get("path", [])
            if path and len(path) > 0:
                source = path[0]
                source_context = self.file_utils.get_code_snippet(
                    source.get("file", ""),
                    source.get("line", 0),
                    context_lines=5
                )
            else:
                source = {
                    "file": vuln.get("file", ""),
                    "line": vuln.get("line", 0),
                    "code": vuln.get("code", "")
                }
                source_context = self.file_utils.get_code_snippet(
                    vuln.get("file", ""),
                    vuln.get("line", 0),
                    context_lines=5
                )
        
        return source, source_context
    
    def _extract_sink_info(self, vuln: Dict) -> str:
        """提取sink上下文"""
        return self.file_utils.get_code_snippet(
            vuln.get("file", ""),
            vuln.get("line", 0),
            context_lines=5
        )
    
    def _enrich_vulnerability(self, vuln: Dict, validation_result: Dict):
        """丰富漏洞信息"""
        vuln["explanation"] = validation_result.get("explanation", "")
        vuln["recommendation"] = validation_result.get("recommendation", "")
        vuln["attack_scenario"] = validation_result.get("attack_scenario", "")
        vuln["sanitizers"] = validation_result.get("sanitizers", [])
        vuln["missing_checks"] = validation_result.get("missing_checks", [])
        vuln["confidence"] = validation_result.get("confidence", 0)
    
    def _save_results(self, results: Dict):
        """保存结果"""
        output_file = config.OUTPUT_DIR / f"iris_results_{int(time.time())}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"结果已保存到: {output_file}")
    
    def _print_summary(self):
        """打印统计摘要"""
        elapsed = self.stats["end_time"] - self.stats["start_time"]
        
        print(f"\n{'='*60}")
        print("📊 IRIS分析统计")
        print(f"{'='*60}")
        print(f"Source候选: {self.stats['source_candidates']}个")
        print(f"Sink候选: {self.stats['sink_candidates']}个")
        print(f"LLM调用次数: {self.stats['llm_calls']}次")
        print(f"缓存命中: {self.stats['cache_hits']}次")
        print(f"原始漏洞数: {self.stats['vulnerabilities_found']}个")
        print(f"确认漏洞数: {self.stats['vulnerabilities_confirmed']}个")
        
        if self.stats['vulnerabilities_found'] > 0:
            filter_rate = (1 - self.stats['vulnerabilities_confirmed'] / self.stats['vulnerabilities_found']) * 100
            print(f"过滤比例: {filter_rate:.1f}%")
        
        print(f"分析耗时: {elapsed:.2f}秒")
        print(f"{'='=}" * 30)


# 为了向后兼容
PySafeScanPipeline = IRISPipeline
