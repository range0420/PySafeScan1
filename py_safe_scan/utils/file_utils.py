"""文件工具函数"""

import logging
from pathlib import Path
from typing import List, Optional, Set
import linecache
import os

logger = logging.getLogger(__name__)


class FileUtils:
    """文件工具类"""
    
    @staticmethod
    def read_file(file_path: Path) -> Optional[str]:
        """
        读取文件内容
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件内容，失败返回None
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # 尝试其他编码
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    return f.read()
            except Exception as e:
                logger.error(f"读取文件失败 {file_path}: {e}")
                return None
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return None
    
    @staticmethod
    def find_python_files(
        directory: Path, 
        recursive: bool = True, 
        max_files: int = 1000,
        ignore_patterns: Set[str] = None
    ) -> List[Path]:
        """
        查找目录中的Python文件
        
        Args:
            directory: 目录路径
            recursive: 是否递归查找
            max_files: 最大文件数
            ignore_patterns: 忽略的模式
            
        Returns:
            Python文件路径列表
        """
        if ignore_patterns is None:
            ignore_patterns = {
                'test_', 'tests/', 'venv/', 'env/', '.venv/', '.env/',
                '__pycache__', 'node_modules', 'dist/', 'build/',
                'examples/', 'docs/', 'migrations/', '.git/'
            }
        
        python_files = []
        
        if recursive:
            pattern = '**/*.py'
        else:
            pattern = '*.py'
        
        for py_file in directory.glob(pattern):
            if len(python_files) >= max_files:
                logger.warning(f"达到最大文件数限制 ({max_files})")
                break
            
            if py_file.is_file():
                # 检查是否应该忽略
                str_path = str(py_file)
                should_ignore = any(pattern in str_path for pattern in ignore_patterns)
                
                if not should_ignore:
                    python_files.append(py_file)
        
        return sorted(python_files)
    
    @staticmethod
    def get_code_snippet(file_path: str, line_number: int, context_lines: int = 5) -> str:
        """
        获取代码片段
        
        Args:
            file_path: 文件路径
            line_number: 行号
            context_lines: 上下文行数
            
        Returns:
            代码片段
        """
        # 基准测试的基础路径
        benchmark_base = Path("/home/hanahanarange/PySafeScan/tests/BenchmarkPython/testcode")
        
        # 尝试不同的路径组合
        possible_paths = [
            Path(file_path),  # 原始路径
            benchmark_base / Path(file_path).name,  # 基准测试目录下的文件
            Path.cwd() / "tests" / "BenchmarkPython" / "testcode" / Path(file_path).name,  # 相对路径
        ]
        
        # 查找存在的文件
        full_path = None
        for path in possible_paths:
            if path.exists():
                full_path = path
                logger.debug(f"找到文件: {full_path}")
                break
        
        if not full_path:
            return f"文件不存在: {file_path}"
        
        start_line = max(1, line_number - context_lines)
        end_line = line_number + context_lines
        
        lines = []
        for i in range(start_line, end_line + 1):
            line = linecache.getline(str(full_path), i)
            if line:
                prefix = "→ " if i == line_number else "  "
                lines.append(f"{prefix}{i:4d}: {line.rstrip()}")
        
        if not lines:
            return f"无法读取文件内容: {file_path}"
        
        return "\n".join(lines)
    
    @staticmethod
    def is_safe_path(base_path: Path, user_path: str) -> bool:
        """
        检查路径是否安全（防止路径遍历）
        
        Args:
            base_path: 基础路径
            user_path: 用户提供的路径
            
        Returns:
            是否安全
        """
        try:
            # 规范化路径
            full_path = (base_path / user_path).resolve()
            
            # 检查是否在基础路径内
            return str(full_path).startswith(str(base_path.resolve()))
        except Exception:
            return False
    
    @staticmethod
    def get_file_hash(file_path: Path) -> str:
        """获取文件哈希值"""
        import hashlib
        
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""
    
    @staticmethod
    def ensure_directory(directory: Path):
        """确保目录存在"""
        directory.mkdir(parents=True, exist_ok=True)
    
    @staticmethod
    def get_project_structure(directory: Path) -> dict:
        """获取项目结构"""
        structure = {
            "root": str(directory),
            "files": [],
            "directories": []
        }
        
        try:
            for item in directory.iterdir():
                if item.is_file():
                    structure["files"].append(item.name)
                elif item.is_dir():
                    structure["directories"].append(item.name)
        except Exception as e:
            logger.error(f"获取项目结构失败: {e}")
        
        return structure
