# PySafeScan - LLM增强的Python漏洞检测工具

基于IRIS论文架构的智能Python安全漏洞检测系统，结合CodeQL静态分析和DeepSeek大语言模型，实现高精度、低误报的漏洞检测。

## ✨ 特性

- 🔍 **CodeQL集成**：使用GitHub CodeQL进行深度静态分析
- 🧠 **LLM增强**：DeepSeek大语言模型智能分析漏洞路径
- 🎯 **IRIS架构**：完整实现论文四阶段方法论
  - 候选规范提取
  - LLM规范推断
  - 污点分析
  - 路径验证
- 📊 **多CWE支持**：支持SQL注入、命令注入、XSS等20+种漏洞类型
- 🚀 **智能缓存**：LLM调用结果缓存，提升效率
- 📈 **详细报告**：生成SARIF/JSON格式分析报告

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/PySafeScan.git
cd PySafeScan

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt
