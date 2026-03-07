"""主流水线 - 完整实现IRIS四阶段"""

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
    """IRIS论文完整实现的主流水线"""
    
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
            "vulnerabilities_confirmed": 0,
            "start_time": None,
            "end_time": None
        }
    
    def analyze_directory(self, directory: Path) -> Dict:
        """
        分析目录 - IRIS四阶段完整实现
        
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
        
        # ============ 阶段2: 运行CodeQL内置查询并提取规范 ============
        logger.info("="*60)
        logger.info("阶段2/4: 运行CodeQL查询并提取规范")
        logger.info("="*60)
        
        # 2.1 运行内置查询
        logger.info("运行CodeQL内置安全查询...")
        results_path = self.codeql.run_builtin_queries(db_path)
        
        # 2.2 从结果中提取API规范
        logger.info("从查询结果中提取API规范...")
        specs = self._extract_specs_from_results(results_path)
        
        self.stats["source_candidates"] = len(specs.get("sources", []))
        self.stats["sink_candidates"] = len(specs.get("sinks", []))
        
        logger.info(f"提取结果:")
        logger.info(f"  - Source候选: {self.stats['source_candidates']}个")
        logger.info(f"  - Sink候选: {self.stats['sink_candidates']}个")
        
        # ============ 阶段3: 解析漏洞结果 ============
        logger.info("="*60)
        logger.info("阶段3/4: 解析漏洞结果")
        logger.info("="*60)
        
        raw_vulnerabilities = self.codeql.extract_results(results_path)
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
                "sources": specs.get("sources", [])[:20],
                "sinks": specs.get("sinks", [])[:20]
            }
        }
        
        # 保存结果
        self._save_results(results)
        
        # 打印统计
        self._print_summary()
        
        return results
    
    def analyze_file(self, file_path: Path) -> Dict:
        """分析单个文件 - 为基准测试优化"""
        # 创建临时目录只包含这个文件
        import tempfile
        import shutil
    
        temp_dir = Path(tempfile.mkdtemp(prefix=f"benchmark_{file_path.stem}_"))
        try:
            # 复制文件到临时目录
            shutil.copy2(file_path, temp_dir / file_path.name)
        
            # 分析临时目录
            results = self.analyze_directory(temp_dir)
        
            return results
        finally:
            # 清理临时目录
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _create_database(self, directory: Path) -> Path:
        """创建CodeQL数据库"""
        try:
            return self.codeql.create_database(directory, language="python")
        except Exception as e:
            logger.error(f"创建数据库失败: {e}")
            raise
    
    def _extract_specs_from_results(self, results_path: Path) -> Dict:
        """
        从CodeQL结果中提取source/sink规范
        """
        # print("\n" + "="*50)
        # print("🔍 进入第二阶段: LLM规范推断")
        # print("="*50)
        
        try:
            # 使用spec_extractor从结果中提取API信息
            apis_data = self.spec_extractor.extract_from_results(results_path)
            
            # 获取所有API（不分类）
            all_apis = apis_data.get("vulnerability_apis", [])
            
            # print(f"📊 提取到 {len(all_apis)} 个候选API")
            logger.info(f"提取到 {len(all_apis)} 个候选API，准备用LLM分类")
            
            # 如果没有API，直接返回
            if not all_apis:
                # print("❌ 没有提取到任何API")
                return {"sources": [], "sinks": [], "all_apis": []}
            
            # 转换为字典格式供LLM使用
            api_dicts = []
            for api in all_apis:
                api_dicts.append({
                    "package": api.package,
                    "class": api.class_name,
                    "method": api.method,
                    "file": api.file,
                    "line": api.line,
                    "context": api.context
                })
            
            # 打印前5个API - 注释掉
            # print("\n📋 前5个候选API:")
            # for i, api in enumerate(api_dicts[:5]):
            #     print(f"  {i+1}. {api['package']}.{api['method']} at {api['file']}:{api['line']}")
            #     print(f"     上下文: {api['context'][:50]}...")
            
            # 用LLM推断这些API的类型（第二阶段）
            if api_dicts and self.cwe_type:
                # print(f"\n🤔 调用LLM进行规范推断（第二阶段）: {len(api_dicts)}个API")
                
                # 获取CWE描述和few-shot示例
                cwe_desc = CWE_DESCRIPTIONS.get(self.cwe_type, "")
                few_shot = FEW_SHOT_EXAMPLES.get(self.cwe_type, [])
                
                # print(f"📌 CWE类型: {self.cwe_type}")
                # print(f"📌 CWE描述: {cwe_desc}")
                # print(f"📌 Few-shot示例数: {len(few_shot)}")
                
                inferred_apis = self.deepseek.infer_source_sink_specs(
                    apis=api_dicts,
                    cwe_type=self.cwe_type,
                    cwe_description=cwe_desc,
                    few_shot_examples=few_shot
                )
                
                # 分类LLM返回的结果
                sources = [a for a in inferred_apis if a.get("llm_label") == "source" and a.get("llm_confidence", 0) > 60]
                sinks = [a for a in inferred_apis if a.get("llm_label") == "sink" and a.get("llm_confidence", 0) > 60]
                
                # print(f"\n📊 LLM分类结果:")
                # print(f"  - 总API数: {len(inferred_apis)}")
                # print(f"  - Sources: {len(sources)}个")
                # print(f"  - Sinks: {len(sinks)}个")
                
                # 打印source示例 - 注释掉
                # if sources:
                #     print("\n✅ Source示例:")
                #     for s in sources[:3]:
                #         print(f"    - {s.get('package')}.{s.get('method')} (置信度: {s.get('llm_confidence')})")
                #         print(f"      解释: {s.get('explanation', '')[:100]}...")
                
                # 打印sink示例 - 注释掉
                # if sinks:
                #     print("\n⚠️ Sink示例:")
                #     for s in sinks[:3]:
                #         print(f"    - {s.get('package')}.{s.get('method')} (置信度: {s.get('llm_confidence')})")
                #         print(f"      解释: {s.get('explanation', '')[:100]}...")
                
                # 更新统计
                self.stats["llm_calls"] += 1
                
                return {
                    "sources": sources,
                    "sinks": sinks,
                    "all_apis": inferred_apis
                }
            else:
                # print(f"❌ 无法调用LLM: api_dicts={bool(api_dicts)}, cwe_type={self.cwe_type}")
                pass
            
            return {"sources": [], "sinks": [], "all_apis": []}
            
        except Exception as e:
            # print(f"❌ 提取规范失败: {e}")
            logger.error(f"提取规范失败: {e}")
            import traceback
            traceback.print_exc()
            return {"sources": [], "sinks": [], "all_apis": []}
    
    def _enhance_specs_with_llm(self, sources: List[Dict], sinks: List[Dict]) -> Dict:
        """
        用LLM增强提取的规范
        """
        if not (sources or sinks) or not self.cwe_type:
            return {"sources": sources, "sinks": sinks}
        
        try:
            # 获取CWE描述和few-shot示例
            cwe_desc = CWE_DESCRIPTIONS.get(self.cwe_type, "")
            few_shot = FEW_SHOT_EXAMPLES.get(self.cwe_type, [])
            
            # 合并所有API
            all_apis = sources + sinks
            
            # 调用LLM重新评估
            inferred_apis = self.deepseek.infer_source_sink_specs(
                apis=all_apis,
                cwe_type=self.cwe_type,
                cwe_description=cwe_desc,
                few_shot_examples=few_shot
            )
            
            self.stats["llm_calls"] += 1
            
            # 重新分类
            enhanced_sources = [a for a in inferred_apis if a.get("llm_label") == "source" and a.get("llm_confidence", 0) > 60]
            enhanced_sinks = [a for a in inferred_apis if a.get("llm_label") == "sink" and a.get("llm_confidence", 0) > 60]
            
            logger.info(f"LLM增强结果:")
            logger.info(f"  - Sources: {len(enhanced_sources)}/{len(sources)}")
            logger.info(f"  - Sinks: {len(enhanced_sinks)}/{len(sinks)}")
            
            return {
                "sources": enhanced_sources,
                "sinks": enhanced_sinks
            }
            
        except Exception as e:
            logger.error(f"LLM增强失败: {e}")
            return {"sources": sources, "sinks": sinks}
    
    def _validate_paths(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """验证漏洞路径 - LLM上下文分析"""
        if not vulnerabilities:
            return []
        
        confirmed = []
        
        for i, vuln in enumerate(vulnerabilities):
            # 检查缓存
            cache_key = f"path_validate_{vuln.get('file')}_{vuln.get('line')}_{vuln.get('cwe', 'unknown')}"
            if self.cache and self.cache.exists(cache_key):
                cached = self.cache.get(cache_key)
                if cached.get("is_vulnerable", False) and cached.get("confidence", 0) > 70:
                    vuln["explanation"] = cached.get("explanation", "")
                    vuln["recommendation"] = cached.get("recommendation", "")
                    vuln["confidence"] = cached.get("confidence", 0)
                    confirmed.append(vuln)
                self.stats["cache_hits"] += 1
                continue
            
            # 提取source和sink信息
            if "source" in vuln:
                source = vuln["source"]
                source_context = self.file_utils.get_code_snippet(
                    source.get("file", ""), 
                    source.get("line", 0),
                    context_lines=5
                )
            else:
                # 如果没有source，使用path中的第一个位置
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
            
            # sink就是漏洞位置
            sink = {
                "file": vuln.get("file", ""),
                "line": vuln.get("line", 0),
                "code": vuln.get("code", "")
            }
            sink_context = self.file_utils.get_code_snippet(
                vuln.get("file", ""),
                vuln.get("line", 0),
                context_lines=5
            )
            
            path = vuln.get("path", [])
            
            code_snippets = {
                "source": source_context,
                "sink": sink_context
            }
            
            # 调用LLM验证
            validation_result = self.deepseek.validate_vulnerability_path(
                source=source,
                sink=sink,
                path=path,
                cwe_type=self.cwe_type or vuln.get("cwe", "unknown"),
                code_snippets=code_snippets
            )
            
            self.stats["llm_calls"] += 1
            
            # 保存缓存
            if self.cache:
                self.cache.set(cache_key, validation_result)
            
            # 如果验证通过，添加到确认列表 - 修改变量名从 validation 到 validation_result
            if validation_result.get("is_vulnerable", False) and validation_result.get("confidence", 0) > 70:
                vuln["explanation"] = validation_result.get("explanation", "")
                vuln["recommendation"] = validation_result.get("recommendation", "")
                vuln["attack_scenario"] = validation_result.get("attack_scenario", "")
                vuln["sanitizers"] = validation_result.get("sanitizers", [])
                vuln["missing_checks"] = validation_result.get("missing_checks", [])
                vuln["confidence"] = validation_result.get("confidence", 0)
                confirmed.append(vuln)
        
        return confirmed
    
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
