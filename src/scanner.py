import os
import sys
import concurrent.futures
from datetime import datetime

# 解决路径加载问题
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.cli import main as single_scan

def scan_file_safe(file_path):
    """带异常捕获的单文件扫描"""
    try:
        # print(f"🔍 正在审计: {os.path.relpath(file_path)}")
        single_scan(file_path)
    except Exception as e:
        print(f"⚠️ 跳过文件 {file_path} (原因: {str(e)})")

def start_mega_scan(target_path):
    """
    完善版：支持目录递归扫描或单个文件扫描
    """
    start_time = datetime.now()
    py_files = []

    # 判断是目录还是文件
    if os.path.isdir(target_path):
        print(f"🚀 PySafeScan 启动目录扫描 | 目标: {target_path}")
        for root, _, files in os.walk(target_path):
            if any(x in root for x in ['venv', '.git', '__pycache__', 'dist']):
                continue
            for file in files:
                if file.endswith(".py"):
                    py_files.append(os.path.join(root, file))
    elif os.path.isfile(target_path) and target_path.endswith(".py"):
        print(f"🚀 PySafeScan 启动单文件扫描 | 目标: {target_path}")
        py_files.append(target_path)
    else:
        print(f"❌ 错误: {target_path} 不是有效的 Python 文件或目录")
        return

    print("-" * 60)

    # 并发审计
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(scan_file_safe, py_files)

    duration = datetime.now() - start_time
    print("-" * 60)
    print(f"✅ 审计完成! 耗时: {duration.total_seconds():.2f}s | 处理文件数: {len(py_files)}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        start_mega_scan(sys.argv[1])
    else:
        print("Usage: python3 src/scanner.py <path_to_file_or_dir>")
