"""CodeQL管理器 - 负责数据库创建和查询执行"""

import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional

import config  # 添加这个导入

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
        
        cmd = [
            self.codeql_path, "database", "analyze",
            str(db_path),
            "--format=sarif-latest",
            f"--output={result_path}",
            "codeql/python-queries"
        ]
        
        logger.info("运行内置Python安全查询")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=600
            )
            logger.info(f"分析完成，结果保存到: {result_path}")
            return result_path
        except subprocess.TimeoutExpired:
            raise Exception("查询运行超时")
        except subprocess.CalledProcessError as e:
            logger.error(f"查询运行失败: {e.stderr}")
            raise Exception(f"CodeQL查询失败: {e.stderr}")
    
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
            "--threads=4",
            "--ram=4096",
            str(query_path)
        ]
        
        logger.info(f"运行自定义查询: {query_path.name}")
        logger.debug(f"命令: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=config.TIMEOUT_SECONDS  # 现在可以访问config了
            )
            logger.info(f"自定义查询完成: {result_path}")
            
            if result.stderr:
                logger.debug(f"查询stderr: {result.stderr}")
                
            return result_path
            
        except subprocess.TimeoutExpired:
            logger.error("查询运行超时")
            raise Exception("自定义查询超时")
        except subprocess.CalledProcessError as e:
            logger.error(f"查询运行失败: {e.stderr}")
            if result_path.exists():
                logger.info(f"但有部分结果文件: {result_path}")
                return result_path
            raise Exception(f"CodeQL自定义查询失败: {e.stderr}")
    
    def _parse_location(self, location: Dict) -> Optional[Dict]:
        """解析位置节点"""
        try:
            loc = location.get("location", {})
            physical = loc.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            
            message = location.get("message", {}).get("text", "")
            
            code = ""
            if "ControlFlowNode for" in message:
                code = message.replace("ControlFlowNode for ", "")
            else:
                code = region.get("snippet", {}).get("text", "")
            
            return {
                "file": artifact.get("uri", ""),
                "line": region.get("startLine", 0),
                "code": code,
                "step": location.get("step", 0)
            }
        except:
            return None

    def _parse_result(self, result: Dict, rule_to_cwe: Dict) -> Optional[Dict]:
        """解析单个结果 - 改进版，提取source和sink信息"""
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
            
            # 提取source信息（从path_nodes的第一个节点）
            source_info = {}
            if path_nodes:
                first_node = path_nodes[0]
                source_info = {
                    "file": first_node.get("file", ""),
                    "line": first_node.get("line", 0),
                    "code": first_node.get("code", "")
                }
            else:
                # 如果没有path_nodes，尝试从relatedLocations获取
                related_locations = result.get("relatedLocations", [])
                if related_locations:
                    first_rel = related_locations[0]
                    phys = first_rel.get("physicalLocation", {})
                    art = phys.get("artifactLocation", {})
                    reg = phys.get("region", {})
                    source_info = {
                        "file": art.get("uri", ""),
                        "line": reg.get("startLine", 0),
                        "code": reg.get("snippet", {}).get("text", "")
                    }
            
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
                "source": source_info,  # 添加source字段
                "raw": result
            }
            
            return vuln
            
        except Exception as e:
            logger.debug(f"解析单个结果失败: {e}")
            return None

    def _should_ignore_path(self, vuln: Dict) -> bool:
        """启发式规则：判断路径是否应该被忽略"""
        message = vuln.get("message", "").lower()
        code = vuln.get("code", "").lower()
        
        ignore_patterns = [
            "import ", "from ", "def ", "class ", "@",
            "log.", "logger.", "debug(", "info(", "warn(", "error(",
            "test", "assert", "assertEquals", "assertTrue",
            "try:", "except", "finally", "raise ",
            "int(", "str(", "float(", "bool(",
        ]
        
        for pattern in ignore_patterns:
            if pattern in message or pattern in code:
                return True
        return False

    def extract_results(self, sarif_path: Path) -> List[Dict]:
        """
        从SARIF文件提取漏洞结果
        """
        vulnerabilities = []
        
        if not sarif_path.exists():
            logger.warning(f"SARIF文件不存在: {sarif_path}")
            return vulnerabilities
        
        try:
            with open(sarif_path, 'r', encoding='utf-8') as f:
                sarif = json.load(f)
            
            rule_to_cwe = {
                "py/sql-injection": "CWE-89",
                "py/path-injection": "CWE-22",
                "py/command-line-injection": "CWE-78",
                "py/xss": "CWE-79",
            }
            
            # 用文件+行号简单去重
            seen = set()
            
            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    vuln = self._parse_result(result, rule_to_cwe)
                    if vuln:
                        key = f"{vuln.get('file')}:{vuln.get('line')}"
                        if key not in seen:
                            seen.add(key)
                            vulnerabilities.append(vuln)
            
            logger.info(f"从SARIF文件中提取了 {len(vulnerabilities)} 个唯一漏洞")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"解析SARIF文件失败: {e}")
            return vulnerabilities

    def _parse_related_location(self, location: Dict) -> Optional[Dict]:
        """解析相关位置"""
        try:
            physical = location.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            
            return {
                "file": artifact.get("uri", ""),
                "line": region.get("startLine", 0),
                "code": region.get("snippet", {}).get("text", ""),
                "step": 0
            }
        except:
            return None

