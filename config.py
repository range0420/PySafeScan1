"""PySafeScan配置文件"""

import os
from pathlib import Path

# ============ 基础路径配置 ============
# 项目根目录
BASE_DIR = Path(__file__).parent

# 输出目录
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

# 缓存目录
CACHE_DIR = BASE_DIR / "cache"
CACHE_DIR.mkdir(exist_ok=True)

# 日志目录
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# ============ CodeQL配置 ============
CODEQL_PATH = os.environ.get("CODEQL_PATH", "codeql")
CODEQL_WORKSPACE = BASE_DIR / ".codeql_workspace"
CODEQL_WORKSPACE.mkdir(exist_ok=True)

# ============ DeepSeek API配置 ============
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_API_URL = os.environ.get("DEEPSEEK_API_URL", "https://api.deepseek.com/v1")
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")

# ============ LLM调用配置 ============
MAX_TOKENS = 4000
TEMPERATURE = 0.1
BATCH_SIZE = 20  # API批处理大小
REQUEST_TIMEOUT = 60  # 请求超时时间（秒）

# ============ 缓存配置 ============
CACHE_TTL = 7 * 24 * 60 * 60  # 缓存有效期：7天
CACHE_MAX_SIZE = 1000  # 内存缓存最大条目数

# ============ 支持的CWE类型 ============
SUPPORTED_CWES = [
    # 注入类
    "CWE-22",   # 路径遍历
    "CWE-78",   # 命令注入
    "CWE-79",   # 跨站脚本
    "CWE-89",   # SQL注入
    "CWE-90",   # LDAP注入
    "CWE-94",   # 代码注入
    "CWE-117",  # 日志注入
    "CWE-643",  # XPath注入
    "CWE-918",  # SSRF
    
    # XXE
    "CWE-611",  # XXE注入
    
    # 加密与随机数
    "CWE-326",  # 弱加密密钥
    "CWE-327",  # 加密问题
    "CWE-328",  # 哈希问题
    "CWE-330",  # 弱随机数
    
    # 配置错误
    "CWE-215",  # 调试信息泄露
    "CWE-693",  # 安全配置错误
    "CWE-942",  # CORS配置不当
    
    # 重定向
    "CWE-601",  # URL重定向
    
    # 硬编码凭证
    "CWE-321",  # 硬编码密钥
    "CWE-798",  # 硬编码凭证
    
    # 信息泄露
    "CWE-209",  # 错误信息泄露
    "CWE-312",  # 敏感数据明文存储
    "CWE-532",  # 敏感数据日志记录
    
    # 反序列化
    "CWE-502",  # 不安全反序列化
]

# ============ CWE到CodeQL查询的映射 ============
CWE_TO_QUERY = {
    "CWE-22": "py/path-injection",
    "CWE-78": "py/command-line-injection",
    "CWE-79": "py/xss",
    "CWE-89": "py/sql-injection",
    "CWE-90": "py/ldap-injection",
    "CWE-94": "py/code-injection",
    "CWE-117": "py/log-injection",
    "CWE-321": "py/hardcoded-key",
    "CWE-326": "py/weak-cryptographic-key",
    "CWE-327": "py/weak-crypto",
    "CWE-328": "py/weak-sensitive-data-hashing",
    "CWE-330": "py/weak-rand",
    "CWE-502": "py/unsafe-deserialization",
    "CWE-601": "py/url-redirect",
    "CWE-611": "py/xxe",
    "CWE-643": "py/xpath-injection",
    "CWE-798": "py/hardcoded-credentials",
    "CWE-918": "py/request-forgery",
}

# ============ 日志配置 ============
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FILE = LOG_DIR / "pysafescan.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# ============ 分析配置 ============
MAX_FILE_SIZE = 10 * 1024 * 1024  # 最大文件大小：10MB
MAX_FILES_PER_PROJECT = 1000  # 每个项目最大文件数
TIMEOUT_SECONDS = 600  # 分析超时时间：10分钟

# ============ IRIS特定配置 ============
IRIS_CONFIG = {
    # 置信度阈值
    "SOURCE_CONFIDENCE_THRESHOLD": 60,  # source置信度阈值
    "SINK_CONFIDENCE_THRESHOLD": 60,    # sink置信度阈值
    "VALIDATION_CONFIDENCE_THRESHOLD": 70,  # 路径验证置信度阈值
    
    # 批处理大小
    "API_BATCH_SIZE": 20,    # API推断批处理
    "PATH_BATCH_SIZE": 5,    # 路径验证批处理
    
    # 最大数量限制
    "MAX_EXTERNAL_APIS": 500,    # 最大外部API数量
    "MAX_PUBLIC_FUNCTIONS": 200,  # 最大公开函数数量
    "MAX_PATH_STEPS": 15,         # 最大路径步骤数
    
    # 是否启用公开函数参数推断
    "ENABLE_FUNCTION_PARAM_INFERENCE": True,
    
    # 是否启用README分析
    "ENABLE_README_ANALYSIS": True,
}

# ============ 性能配置 ============
PERFORMANCE_CONFIG = {
    "ENABLE_PARALLEL": True,        # 启用并行处理
    "MAX_WORKERS": 4,                # 最大工作线程数
    "ENABLE_STREAMING": False,       # 启用流式响应
    "CACHE_LLM_RESPONSES": True,     # 缓存LLM响应
}
