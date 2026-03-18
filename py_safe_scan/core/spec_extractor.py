"""规范提取器 - 从CodeQL结果中提取候选API"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class API:
    """API信息"""
    package: str
    class_name: str
    method: str
    file: str
    line: int
    context: str
    
    def to_dict(self) -> Dict:
        return {
            "package": self.package,
            "class": self.class_name,
            "method": self.method,
            "file": self.file,
            "line": self.line,
            "context": self.context
        }

class SpecExtractor:
    """从CodeQL结果中提取候选API（IRIS第一阶段）"""
    
    def __init__(self, codeql_manager):
        self.codeql = codeql_manager
    
    def extract_candidate_apis(self, db_path: Path) -> List[API]:
        """
        提取所有候选API（不再区分source/sink）
        这是IRIS论文的第一阶段：候选提取
        """
        # 先创建自定义查询文件
        query_path = self._ensure_extract_query()
        
        # 运行自定义查询
        logger.info("运行API提取查询...")
        results_path = self.codeql.run_custom_query(db_path, query_path)
        
        apis = []
        if results_path and results_path.exists():
            with open(results_path, 'r', encoding='utf-8') as f:
                sarif = json.load(f)
            
            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    api = self._parse_api_from_result(result)
                    if api:
                        apis.append(api)
        
        logger.info(f"提取到 {len(apis)} 个候选API")
        return apis
    
    def _ensure_extract_query(self) -> Path:
        """确保提取API的查询文件存在"""
        query_dir = Path("/home/hanahanarange/PySafeScan/custom-queries")
        query_dir.mkdir(exist_ok=True)
        
        query_path = query_dir / "extract_apis.ql"
        
        if not query_path.exists():
            with open(query_path, 'w') as f:
                f.write("""
/**
 * @name Extract All API Calls
 * @description 提取项目中所有函数调用，用于LLM分类
 * @kind problem
 * @id pysafescan/extract-apis
 */

import python
import semmle.python.ApiGraphs

from Call call
select call.getLocation().getFile().getBaseName(),
       call.getLocation().getStartLine(),
       call.toString()
""")
            logger.info(f"创建查询文件: {query_path}")
        
        return query_path
    
    def _parse_api_from_result(self, result: Dict) -> Optional[API]:
        """从SARIF结果中解析API信息"""
        try:
            locations = result.get("locations", [])
            if not locations:
                return None
            
            loc = locations[0]
            physical = loc.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            
            file_path = artifact.get("uri", "")
            line = region.get("startLine", 0)
            
            # 从message中获取API信息
            message = result.get("message", {}).get("text", "")
            
            # 解析message格式: "file.py", 123, "func()"
            parts = message.split(',')
            if len(parts) >= 3:
                api_str = parts[2].strip().strip('"')
            else:
                api_str = message
            
            # 尝试解析包名、类名、方法名
            package = "unknown"
            class_name = ""
            method = api_str.split('(')[0].strip()
            
            if '.' in method:
                parts = method.split('.')
                if len(parts) >= 2:
                    class_name = parts[-2]
                    method = parts[-1]
            
            # 获取上下文
            context = self._get_context(file_path, line)
            
            return API(
                package=package,
                class_name=class_name,
                method=method,
                file=file_path,
                line=line,
                context=context
            )
        except Exception as e:
            logger.debug(f"解析API失败: {e}")
            return None
    
    def _get_context(self, file_path: str, line: int) -> str:
        """获取代码上下文"""
        from py_safe_scan.utils.file_utils import FileUtils
        return FileUtils.get_code_snippet(file_path, line, 3)
