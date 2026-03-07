"""LLM模块"""
from py_safe_scan.llm.deepseek_client import DeepSeekClient
from py_safe_scan.llm.prompts import (
    CWE_DESCRIPTIONS, 
    FEW_SHOT_EXAMPLES, 
    SYSTEM_PROMPT_SPEC_INFERENCE,
    SYSTEM_PROMPT_PATH_VALIDATION,
    SYSTEM_PROMPTS
)

__all__ = [
    'DeepSeekClient', 
    'CWE_DESCRIPTIONS', 
    'FEW_SHOT_EXAMPLES',
    'SYSTEM_PROMPT_SPEC_INFERENCE',
    'SYSTEM_PROMPT_PATH_VALIDATION',
    'SYSTEM_PROMPTS'
]
