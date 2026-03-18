"""SARIF报告生成器 - 生成符合SARIF规范的漏洞报告"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class SARIFGenerator:
    """SARIF报告生成器"""
    
    def __init__(self):
        self.version = "2.1.0"
        self.schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        
    def generate(self, results: Dict, output_path: Path):
        """
        生成SARIF报告
        
        Args:
            results: PySafeScan分析结果
            output_path: 输出路径
        """
        sarif_log = self._create_sarif_log(results)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_log, f, indent=2, ensure_ascii=False)
        
        logger.info(f"SARIF报告已生成: {output_path}")
    
    def _create_sarif_log(self, results: Dict) -> Dict:
        """创建SARIF日志"""
        return {
            "$schema": self.schema,
            "version": self.version,
            "runs": [self._create_run(results)]
        }
    
    def _create_run(self, results: Dict) -> Dict:
        """创建运行信息"""
        return {
            "tool": self._create_tool_info(),
            "invocations": [self._create_invocation(results)],
            "results": self._create_results(results.get("vulnerabilities", [])),
            "properties": {
                "stats": results.get("stats", {})
            }
        }
    
    def _create_tool_info(self) -> Dict:
        """创建工具信息"""
        return {
            "driver": {
                "name": "PySafeScan",
                "version": "0.1.0",
                "informationUri": "https://github.com/yourteam/PySafeScan",
                "rules": self._create_rules()
            }
        }
    
    def _create_rules(self) -> List[Dict]:
        """创建规则列表"""
        from py_safe_scan.llm.prompts import CWE_DESCRIPTIONS
        
        rules = []
        for cwe, desc in CWE_DESCRIPTIONS.items():
            rule_id = cwe.replace("-", "")
            rules.append({
                "id": rule_id,
                "name": cwe,
                "shortDescription": {
                    "text": desc.split(":")[0] if ":" in desc else desc
                },
                "fullDescription": {
                    "text": desc
                },
                "defaultConfiguration": {
                    "level": "error"
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html",
                "properties": {
                    "tags": ["security", "vulnerability", cwe]
                }
            })
        
        return rules
    
    def _create_invocation(self, results: Dict) -> Dict:
        """创建调用信息"""
        stats = results.get("stats", {})
        
        return {
            "startTimeUtc": datetime.fromtimestamp(stats.get("start_time", 0)).isoformat(),
            "endTimeUtc": datetime.fromtimestamp(stats.get("end_time", 0)).isoformat(),
            "executionSuccessful": True,
            "toolExecutionNotifications": [],
            "properties": {
                "filesScanned": stats.get("files_scanned", 0),
                "llmCalls": stats.get("llm_calls", 0),
                "cacheHits": stats.get("cache_hits", 0)
            }
        }
    
    def _create_results(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """创建结果列表"""
        results = []
        
        for i, vuln in enumerate(vulnerabilities):
            result = {
                "ruleId": vuln.get("cwe", "CWE-89").replace("-", ""),
                "ruleIndex": 0,
                "level": self._map_severity(vuln.get("severity", "medium")),
                "message": {
                    "text": vuln.get("description", "安全漏洞")
                },
                "locations": [self._create_location(vuln)],
                "codeFlows": self._create_code_flow(vuln),
                "properties": {
                    "confidence": vuln.get("confidence", 0),
                    "cwe": vuln.get("cwe")
                }
            }
            
            if vuln.get("recommendation"):
                result["fixes"] = [{
                    "description": {
                        "text": vuln["recommendation"]
                    }
                }]
            
            results.append(result)
        
        return results
    
    def _create_location(self, vuln: Dict) -> Dict:
        """创建位置信息"""
        sink = vuln.get("sink", {})
        
        return {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": sink.get("file", vuln.get("file", "")),
                    "uriBaseId": "SRCROOT"
                },
                "region": {
                    "startLine": sink.get("line", vuln.get("line", 0)),
                    "startColumn": 1,
                    "snippet": {
                        "text": sink.get("code", "")
                    }
                }
            },
            "logicalLocations": [{
                "name": sink.get("method", ""),
                "kind": "function"
            }]
        }
    
    def _create_code_flow(self, vuln: Dict) -> List[Dict]:
        """创建代码流信息"""
        path = vuln.get("path", [])
        if not path:
            return []
        
        thread_flows = [{
            "id": 0,
            "locations": []
        }]
        
        for i, node in enumerate(path[:10]):  # 限制长度
            thread_flows[0]["locations"].append({
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
                "state": {
                    "taint": {
                        "text": "污点传播中"
                    }
                },
                "nestingLevel": i
            })
        
        return [{
            "threadFlows": thread_flows
        }]
    
    def _map_severity(self, severity: str) -> str:
        """映射严重性到SARIF级别"""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note"
        }
        return mapping.get(severity, "warning")
