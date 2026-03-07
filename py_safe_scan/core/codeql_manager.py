"""CodeQL管理器 - 负责数据库创建和查询执行"""

import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class CodeQLManager:
    """CodeQL管理器"""
    
    def __init__(self, codeql_path: str = "codeql", workspace_dir: Path = None):
        """
        初始化CodeQL管理器
        
        Args:
            codeql_path: CodeQL可执行文件路径
            workspace_dir: 工作目录
        """
        self.codeql_path = codeql_path
        self.workspace_dir = workspace_dir or Path.cwd() / ".codeql_workspace"
        self.db_dir = self.workspace_dir / "databases"
        self.result_dir = self.workspace_dir / "results"
        
        # 创建目录
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.result_dir.mkdir(parents=True, exist_ok=True)
        
        # 检查CodeQL是否可用
        self._check_codeql()
    
    def _check_codeql(self):
        """检查CodeQL是否可用"""
        try:
            result = subprocess.run(
                [self.codeql_path, "--version"],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info(f"CodeQL版本: {result.stdout.splitlines()[0]}")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise Exception(f"CodeQL不可用: {e}. 请确保codeql在PATH中或设置CODEQL_PATH环境变量")
    
    def create_database(self, source_dir: Path, language: str = "python") -> Path:
        """
        创建CodeQL数据库
        
        Args:
            source_dir: 源代码目录
            language: 语言
            
        Returns:
            数据库路径
        """
        db_name = f"{source_dir.name}.db"
        db_path = self.db_dir / db_name
        
        cmd = [
            self.codeql_path, "database", "create",
            str(db_path),
            f"--language={language}",
            f"--source-root={source_dir}",
            "--overwrite"
        ]
        
        logger.info(f"创建CodeQL数据库: {db_path}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=300  # 5分钟超时
            )
            logger.info("数据库创建成功")
            return db_path
        except subprocess.TimeoutExpired:
            raise Exception("数据库创建超时")
        except subprocess.CalledProcessError as e:
            logger.error(f"数据库创建失败: {e.stderr}")
            raise Exception(f"CodeQL数据库创建失败: {e.stderr}")
    
    def run_builtin_queries(self, db_path: Path) -> Path:
        """
        运行内置的Python安全查询
        
        Args:
            db_path: 数据库路径
            
        Returns:
            SARIF结果文件路径
        """
        result_path = self.result_dir / f"builtin_results.sarif"
        
        # 使用Python安全查询包
        cmd = [
            self.codeql_path, "database", "analyze",
            str(db_path),
            "--format=sarif-latest",
            f"--output={result_path}",
            "codeql/python-queries"  # Python安全查询包
        ]
        
        logger.info("运行内置Python安全查询")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=600  # 10分钟超时
            )
            logger.info(f"分析完成，结果保存到: {result_path}")
            return result_path
        except subprocess.TimeoutExpired:
            raise Exception("查询运行超时")
        except subprocess.CalledProcessError as e:
            logger.error(f"查询运行失败: {e.stderr}")
            raise Exception(f"CodeQL查询失败: {e.stderr}")
    
    def run_security_analysis(self, db_path: Path) -> Path:
        """运行安全分析（run_builtin_queries的别名）"""
        return self.run_builtin_queries(db_path)
    
    def run_custom_query(self, db_path: Path, query_path: Path) -> Path:
        """
        运行自定义查询
        
        Args:
            db_path: 数据库路径
            query_path: 查询文件路径
            
        Returns:
            SARIF结果文件路径
        """
        result_path = self.result_dir / f"{query_path.stem}.sarif"
        
        cmd = [
            self.codeql_path, "database", "analyze",
            str(db_path),
            "--format=sarif-latest",
            f"--output={result_path}",
            str(query_path)
        ]
        
        logger.info(f"运行自定义查询: {query_path.name}")
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=600)
            logger.info(f"自定义查询完成: {result_path}")
            return result_path
        except Exception as e:
            raise Exception(f"自定义查询失败: {e}")
    
    def extract_results(self, sarif_path: Path) -> List[Dict]:
        """
        从SARIF文件提取漏洞结果
        
        Args:
            sarif_path: SARIF文件路径
            
        Returns:
            漏洞列表
        """
        vulnerabilities = []
        
        if not sarif_path.exists():
            logger.warning(f"SARIF文件不存在: {sarif_path}")
            return vulnerabilities
        
        try:
            with open(sarif_path, 'r', encoding='utf-8') as f:
                sarif = json.load(f)
            
            # 规则到CWE的映射
            rule_to_cwe = {
                # 注入类漏洞
                "py/sql-injection": "CWE-89",
                "py/path-injection": "CWE-22",
                "py/command-line-injection": "CWE-78",
                "py/code-injection": "CWE-94",
                "py/xss": "CWE-79",
                "py/reflected-xss": "CWE-79",
                "py/stored-xss": "CWE-79",
                "py/template-injection": "CWE-79",
                "py/unsafe-deserialization": "CWE-502",
                "py/ldap-injection": "CWE-90",
                "py/xpath-injection": "CWE-643",
                "py/xxe": "CWE-611",
                "py/xml-bomb": "CWE-776",
                
                # 加密与随机数
                "py/weak-cryptographic-key": "CWE-326",
                "py/weak-crypto": "CWE-327",
                "py/weak-sensitive-data-hashing": "CWE-328",
                "py/weak-rand": "CWE-330",
                
                # 配置错误
                "py/flask-debug": "CWE-215",
                
                # 重定向
                "py/url-redirection": "CWE-601",
                
                # 硬编码凭证
                "py/hardcoded-credentials": "CWE-798",
                "py/hardcoded-password": "CWE-798",
                "py/hardcoded-key": "CWE-321",
                
                # 信息泄露
                "py/stack-trace-exposure": "CWE-209",
                "py/clear-text-storage-sensitive-data": "CWE-312",
                "py/clear-text-logging-sensitive-data": "CWE-532",
            }
            
            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    vuln = self._parse_result(result, rule_to_cwe)
                    if vuln:
                        vulnerabilities.append(vuln)
            
            logger.info(f"从SARIF文件中提取了 {len(vulnerabilities)} 个漏洞")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"解析SARIF文件失败: {e}")
            return vulnerabilities
    
    def _parse_result(self, result: Dict, rule_to_cwe: Dict) -> Optional[Dict]:
        """解析单个结果 - 改进版，提取source和sink"""
        try:
            rule_id = result.get("ruleId")
            message = result.get("message", {}).get("text", "")
            
            locations = result.get("locations", [])
            if not locations:
                return None
            
            # 获取sink位置（漏洞发生的位置）
            sink_loc = locations[0]
            sink_physical = sink_loc.get("physicalLocation", {})
            sink_artifact = sink_physical.get("artifactLocation", {})
            sink_region = sink_physical.get("region", {})
            
            # 获取source位置（从relatedLocations中找ID为1的）
            source_loc = None
            related_locations = result.get("relatedLocations", [])
            for rel_loc in related_locations:
                if rel_loc.get("id") == 1:  # ID为1的通常是source
                    source_loc = rel_loc
                    break
            
            # 提取污点路径
            path_nodes = []
            code_flows = result.get("codeFlows", [])
            for flow in code_flows:
                thread_flows = flow.get("threadFlows", [])
                for thread_flow in thread_flows:
                    for loc in thread_flow.get("locations", []):
                        node = self._parse_location(loc)
                        if node:
                            path_nodes.append(node)
            
            # 获取CWE
            cwe = rule_to_cwe.get(rule_id, "unknown")
            
            # 提取严重性
            level = result.get("level", "warning")
            if level == "error":
                severity = "high"
            elif level == "warning":
                severity = "medium"
            else:
                severity = "low"
            
            # 构建返回结果
            vuln = {
                "cwe": cwe,
                "rule": rule_id,
                "message": message,
                "file": sink_artifact.get("uri", ""),
                "line": sink_region.get("startLine", 0),
                "code": sink_region.get("snippet", {}).get("text", ""),
                "severity": severity,
                "path": path_nodes,
                "raw": result
            }
            
            # 添加source信息
            if source_loc:
                source_physical = source_loc.get("physicalLocation", {})
                source_artifact = source_physical.get("artifactLocation", {})
                source_region = source_physical.get("region", {})
                vuln["source"] = {
                    "file": source_artifact.get("uri", ""),
                    "line": source_region.get("startLine", 0),
                    "code": source_region.get("snippet", {}).get("text", ""),
                    "message": source_loc.get("message", {}).get("text", "")
                }
            
            return vuln
            
        except Exception as e:
            logger.debug(f"解析单个结果失败: {e}")
            return None
    
    def _extract_path(self, code_flows: List[Dict]) -> List[Dict]:
        """提取污点路径"""
        path_nodes = []
        
        for flow in code_flows:
            thread_flows = flow.get("threadFlows", [])
            for thread_flow in thread_flows:
                locations = thread_flow.get("locations", [])
                for loc in locations:
                    node = self._parse_location(loc)
                    if node:
                        path_nodes.append(node)
        
        return path_nodes
    
    def _parse_location(self, location: Dict) -> Optional[Dict]:
        """解析位置节点"""
        try:
            loc = location.get("location", {})
            physical = loc.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            
            return {
                "file": artifact.get("uri", ""),
                "line": region.get("startLine", 0),
                "code": region.get("snippet", {}).get("text", ""),
                "step": location.get("step", 0)
            }
        except:
            return None
    
    def cleanup(self):
        """清理工作目录"""
        import shutil
        if self.workspace_dir.exists():
            shutil.rmtree(self.workspace_dir)
            logger.info(f"已清理工作目录: {self.workspace_dir}")
