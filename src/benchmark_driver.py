import os
import csv
import json
import sys
from src.core.analyzer import analyze_file
from src.cli import DeepSeekIrisAuditor

# 强制设置 Python 路径，防止 ModuleNotFoundError
sys.path.append(os.getcwd())

class BenchmarkScorer:
    def __init__(self, benchmark_dir):
        self.benchmark_dir = benchmark_dir
        self.testcode_dir = os.path.join(benchmark_dir, "testcode")
        self.csv_path = os.path.join(benchmark_dir, "expectedresults-0.1.csv")
        self.auditor = DeepSeekIrisAuditor()
        self.stats = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

    def load_expected_results(self):
        """硬核索引解析：跳过注释，直接取第1列(文件名)和第3列(真实结果)"""
        answers = {}
        if not os.path.exists(self.csv_path):
            print(f"❌ 找不到答案文件: {self.csv_path}")
            return answers

        print(f"📖 正在解析答案文件: {self.csv_path}")
        with open(self.csv_path, mode='r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # 1. 跳过注释行（以#开头）和空行
                if not line or line.startswith('#'):
                    continue
                
                # 2. 严格按逗号分割
                parts = line.split(',')
                if len(parts) >= 3:
                    # 第一列是测试用例名 (如 BenchmarkTest00001)
                    test_case = parts[0].strip()
                    if not test_case.endswith('.py'):
                        test_case += '.py'
                    
                    # 第三列是 real vulnerability (true/false)
                    # 只要字符串包含 'true' (不区分大小写) 就是 True
                    is_vuln = parts[2].strip().lower() == 'true'
                    answers[test_case] = is_vuln
                else:
                    print(f"⚠️ 警告：第 {line_num} 行格式异常，跳过: {line}")
        
        print(f"✅ 成功加载 {len(answers)} 条标准答案。")
        return answers

    def run_evaluation(self):
        answers = self.load_expected_results()
        if not answers: return

        # 获取所有待测文件并排序
        all_files = sorted([f for f in os.listdir(self.testcode_dir) if f.endswith(".py")])
        total_files = len(all_files)
        
        print(f"🚀 启动全量评测 | 目标: {total_files} 个文件")
        print("-" * 50)

        for i, f_name in enumerate(all_files):
            full_path = os.path.join(self.testcode_dir, f_name)
            expected_vuln = answers.get(f_name, False)
            
            try:
                # 1. 符号分析
                potentials = analyze_file(full_path)
                
                # 2. AI 审计
                system_detected = False
                for p in potentials:
                    res = self.auditor.audit(p['type'], p['slice'], p['spec'])
                    if res['is_vulnerable']:
                        system_detected = True
                        break
                
                # 3. 计分
                if expected_vuln and system_detected: self.stats["TP"] += 1
                elif not expected_vuln and not system_detected: self.stats["TN"] += 1
                elif expected_vuln and not system_detected: self.stats["FN"] += 1
                elif not expected_vuln and system_detected: self.stats["FP"] += 1

                # 实时进度条
                progress = (i + 1) / total_files * 100
                print(f"[{i+1}/{total_files}] {f_name:25} | 预期: {str(expected_vuln):5} | 实际: {str(system_detected):5} | 进度: {progress:.1f}%")

            except Exception as e:
                print(f"⚠️ 处理 {f_name} 时出错: {e}")
                continue

        self.print_scorecard()

    def print_scorecard(self):
        # (保持之前的统计代码不变)
        tp, fp, tn, fn = self.stats["TP"], self.stats["FP"], self.stats["TN"], self.stats["FN"]
        total = sum(self.stats.values())
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        print("\n" + "="*60)
        print("🏆 PySafeScan1 - OWASP Benchmark 工业级成绩单")
        print("="*60)
        print(f"📊 样本总数: {total}")
        print(f"✅ 真阳性率 (Recall): {tpr*100:.2f}%")
        print(f"❌ 假阳性率 (FPR):    {fpr*100:.2f}%")
        print(f"⚖️  Youden's Index:   {(tpr - fpr):.4f}")
        print("-" * 60)
        print(f"TP: {tp} | FP: {fp} | TN: {tn} | FN: {fn}")
        print("="*60)

if __name__ == "__main__":
    scorer = BenchmarkScorer("tests/BenchmarkPython")
    scorer.run_evaluation()
