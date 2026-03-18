import os
import pandas as pd
from src.core.analyzer import analyze_file
from src.cli import DeepSeekIrisAuditor

class MassEvaluator:
    def __init__(self, dataset_path):
        self.dataset_path = dataset_path # 指向下载的 OWASP 数据集目录
        self.results = []

    def run_all(self):
        # 遍历目录下所有 .py 文件
        for root, dirs, files in os.walk(self.dataset_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    # 1. 运行你的分析逻辑
                    res = self.scan_single_file(full_path)
                    self.results.append(res)
        
        # 2. 生成最终的统计表格和正确率看板
        self.generate_report()

    def scan_single_file(self, path):
        # 记录：文件名、检测到的行、AI 判定结果
        # 同时提取文件名中的标签（OWASP 官方文件名通常包含该文件是否为真漏洞的标记）
        is_real_vuln = "TruePositive" in path 
        # ... 调用之前的审计逻辑 ...
        return {"file": path, "expected": is_real_vuln, "actual": system_detected}
