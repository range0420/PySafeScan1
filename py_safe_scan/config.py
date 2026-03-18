"""PySafeScan配置文件 - IRIS完整实现（增强版）"""

import os
from pathlib import Path

# ============ 基础路径配置 ============
BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)
CACHE_DIR = BASE_DIR / "cache"
CACHE_DIR.mkdir(exist_ok=True)
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
BATCH_SIZE = 20
REQUEST_TIMEOUT = 60

# ============ 缓存配置 ============
CACHE_TTL = 7 * 24 * 60 * 60  # 7天
CACHE_MAX_SIZE = 1000

# ============ 支持的CWE类型 ============
SUPPORTED_CWES = [
    "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-94",
    "CWE-117", "CWE-643", "CWE-918", "CWE-611", "CWE-326", "CWE-327",
    "CWE-328", "CWE-330", "CWE-215", "CWE-693", "CWE-942", "CWE-601",
    "CWE-321", "CWE-798", "CWE-209", "CWE-312", "CWE-532", "CWE-502",
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

# ============ 分析配置 ============
MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_FILES_PER_PROJECT = 1000
TIMEOUT_SECONDS = 600

# ============ IRIS特定配置（严格按论文） ============
IRIS_CONFIG = {
    # 阶段1: 候选提取配置
    "EXTRACT_EXTERNAL_APIS": True,
    "EXTRACT_INTERNAL_FUNCTIONS": True,
    "FILTER_TEST_LIBRARIES": True,
    "MAX_EXTERNAL_APIS": 500,
    "MAX_INTERNAL_FUNCTIONS": 200,
    
    # 阶段2: LLM规范推断配置（增强版）
    "SPEC_INFERENCE_BATCH_SIZE": 20,
    "SOURCE_CONFIDENCE_THRESHOLD": 75,  # 提高到75
    "SINK_CONFIDENCE_THRESHOLD": 75,    # 提高到75
    "USE_FEW_SHOT": True,
    "FEW_SHOT_COUNT": 3,
    "ENABLE_MULTI_ROUND_INFERENCE": True,  # 启用多轮推理
    "ENABLE_CONTEXT_ANALYSIS": True,        # 启用上下文分析
    
    # 阶段3: 污点分析配置
    "ENABLE_CUSTOM_QUERIES": False,  # 保持False，使用内置查询
    "MAX_PATH_STEPS": 15,
    
    # 阶段3.5: 规范过滤配置
    "ENABLE_SPEC_FILTERING": True,
    "FILTER_THRESHOLD": 0.5,  # 至少50%的规范匹配
    
    # 阶段4: 上下文验证配置
    "PATH_VALIDATION_BATCH_SIZE": 5,
    "VALIDATION_CONFIDENCE_THRESHOLD": 75,  # 提高到75
    "CONTEXT_LINES": 5,
    "ENABLE_SANITIZER_DETECTION": True,
    "MIN_PATH_LENGTH": 2,
    
    # CWE特定阈值
    "CWE_THRESHOLDS": {
        "CWE-89": 80,   # SQL注入
        "CWE-78": 85,   # 命令注入
        "CWE-22": 80,   # 路径遍历
        "CWE-79": 80,   # XSS
        "CWE-94": 85,   # 代码注入
        "CWE-611": 80,  # XXE
        "CWE-502": 85,  # 反序列化
    },
    
    # 功能开关
    "ENABLE_FUNCTION_PARAM_INFERENCE": True,
    "ENABLE_README_ANALYSIS": True,
    "ENABLE_MULTI_STAGE_FILTERING": True,
    
    # 缓存设置
    "CACHE_SPEC_INFERENCE": True,
    "CACHE_PATH_VALIDATION": True,
}

# ============ 性能配置 ============
PERFORMANCE_CONFIG = {
    "ENABLE_PARALLEL": True,
    "MAX_WORKERS": 4,
    "ENABLE_STREAMING": False,
}
