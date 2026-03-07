"""SARIF解析器 - 解析CodeQL输出的SARIF格式结果"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

class SARIFParser:
    """SARIF格式结果解析器"""
    
    def __init__(self):
        self.version = "2.1.0"
    
    def parse_file(self, sarif_path: Path) -> List[Dict]:
        """
        解析SARIF文件
        
        Args:
            sarif_path: SARIF文件路径
            
        Returns:
            漏洞列表
        """
        if not sarif_path.exists():
            logger.error(f"SARIF文件不存在: {sarif_path}")
            return []
        
        try:
            with open(sarif_path, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
            
            return self._parse_sarif(sarif_data)
        except Exception as e:
            logger.error(f"解析SARIF文件失败: {e}")
            return []
    
    def parse_string(self, sarif_str: str) -> List[Dict]:
        """解析SARIF字符串"""
        try:
            sarif_data = json.loads(sarif_str)
            return self._parse_sarif(sarif_data)
        except Exception as e:
            logger.error(f"解析SARIF字符串失败: {e}")
            return []
    
    def _parse_sarif(self, sarif_data: Dict) -> List[Dict]:
        """解析SARIF数据"""
        vulnerabilities = []
        
        # 获取runs
        runs = sarif_data.get("runs", [])
        if not runs:
            return vulnerabilities
        
        for run in runs:
            # 获取结果
            results = run.get("results", [])
            
            # 获取规则映射
            rules = self._extract_rules(run)
            
            for result in results:
                vuln = self._parse_result(result, rules)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_rules(self, run: Dict) -> Dict:
        """提取规则映射"""
        rules = {}
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        
        # 获取规则列表
        rule_list = driver.get("rules", [])
        for rule in rule_list:
            rule_id = rule.get("id")
            rules[rule_id] = {
                "name": rule.get("name", ""),
                "description": rule.get("shortDescription", {}).get("text", ""),
                "help": rule.get("help", {}).get("text", "")
            }
        
        return rules
    
    def _parse_result(self, result: Dict, rules: Dict) -> Optional[Dict]:
        """解析单个结果"""
        try:
            rule_id = result.get("ruleId")
            rule_info = rules.get(rule_id, {})
            
            # 获取消息
            message = result.get("message", {}).get("text", "")
            
            # 获取位置
            locations = result.get("locations", [])
            if not locations:
                return None
            
            location = locations[0]
            physical_loc = location.get("physicalLocation", {})
            artifact_loc = physical_loc.get("artifactLocation", {})
            region = physical_loc.get("region", {})
            
            file_path = artifact_loc.get("uri", "")
            line = region.get("startLine", 0)
            snippet = region.get("snippet", {}).get("text", "")
            
            # 获取代码流（污点路径）
            code_flows = result.get("codeFlows", [])
            path = self._extract_path(code_flows)
            
            # 获取严重性
            properties = result.get("properties", {})
            severity = properties.get("severity", "medium")
            
            return {
                "cwe": self._extract_cwe(rule_id),
                "rule_id": rule_id,
                "rule_name": rule_info.get("name", ""),
                "description": rule_info.get("description", message),
                "message": message,
                "file": file_path,
                "line": line,
                "code": snippet,
                "severity": severity,
                "path": path,
                "raw": result
            }
        except Exception as e:
            logger.debug(f"解析结果失败: {e}")
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
            physical_loc = loc.get("physicalLocation", {})
            artifact_loc = physical_loc.get("artifactLocation", {})
            region = physical_loc.get("region", {})
            
            return {
                "file": artifact_loc.get("uri", ""),
                "line": region.get("startLine", 0),
                "code": region.get("snippet", {}).get("text", ""),
                "step": location.get("step", 0)
            }
        except:
            return None
    
    def _extract_cwe(self, rule_id: str) -> str:
        """从rule_id中提取CWE编号"""
        import re
        match = re.search(r'CWE-(\d+)', rule_id, re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        return "unknown"
    
    def to_sarif(self, vulnerabilities: List[Dict], tool_name: str = "PySafeScan") -> Dict:
        """将漏洞列表转换为SARIF格式"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": self.version,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "1.0.0",
                        "rules": self._generate_rules(vulnerabilities)
                    }
                },
                "results": self._generate_results(vulnerabilities)
            }]
        }
        return sarif
    
    def _generate_rules(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """生成规则列表"""
        rules = []
        seen_rules = set()
        
        for vuln in vulnerabilities:
            rule_id = vuln.get("rule_id", vuln.get("cwe", "unknown"))
            if rule_id in seen_rules:
                continue
            
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": vuln.get("rule_name", rule_id),
                "shortDescription": {
                    "text": vuln.get("description", "")
                },
                "help": {
                    "text": vuln.get("message", ""),
                    "markdown": vuln.get("message", "")
                }
            })
        
        return rules
    
    def _generate_results(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """生成结果列表"""
        results = []
        
        for vuln in vulnerabilities:
            result = {
                "ruleId": vuln.get("rule_id", vuln.get("cwe", "unknown")),
                "level": self._map_severity(vuln.get("severity", "medium")),
                "message": {
                    "text": vuln.get("message", vuln.get("description", ""))
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": vuln.get("file", "")
                        },
                        "region": {
                            "startLine": vuln.get("line", 0),
                            "snippet": {
                                "text": vuln.get("code", "")
                            }
                        }
                    }
                }]
            }
            
            # 添加代码流（污点路径）
            if vuln.get("path"):
                result["codeFlows"] = [{
                    "threadFlows": [{
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": node.get("file", "")
                                        },
                                        "region": {
                                            "startLine": node.get("line", 0),
                                            "snippet": {
                                                "text": node.get("code", "")
                                            }
                                        }
                                    }
                                },
                                "step": i
                            }
                            for i, node in enumerate(vuln["path"])
                        ]
                    }]
                }]
            
            results.append(result)
        
        return results
    
    def _map_severity(self, severity: str) -> str:
        """映射严重性到SARIF级别"""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note"
        }
        return mapping.get(severity, "warning")
