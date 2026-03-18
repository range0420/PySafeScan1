import os

# 基础路径配置
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")

# API 配置
API_KEY = os.getenv("DEEPSEEK_API_KEY") # 确保你已经 export 了这个环境变量
BASE_URL = "https://api.deepseek.com"
CODEQL_DB_PATH = "iris-db"

# 审计上下文窗口大小（参考 IRIS 的 SNIPPET_CONTEXT_SIZE）
SNIPPET_CONTEXT_SIZE = 30
