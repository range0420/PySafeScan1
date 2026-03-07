"""DeepSeek API客户端"""

import json
import logging
import time
from typing import List, Dict, Optional, Any
from openai import OpenAI

import config
from py_safe_scan.llm.prompts import (
    SYSTEM_PROMPT_SPEC_INFERENCE, 
    SYSTEM_PROMPT_PATH_VALIDATION,
    CWE_DESCRIPTIONS,
    FEW_SHOT_EXAMPLES
)

logger = logging.getLogger(__name__)


class DeepSeekClient:
    """DeepSeek API客户端，用于推断污点规范和验证路径"""
    
    def __init__(self, api_key: str = None, model: str = None):
        """
        初始化DeepSeek客户端
        
        Args:
            api_key: DeepSeek API密钥
            model: 模型名称
        """
        self.api_key = api_key or config.DEEPSEEK_API_KEY
        self.model = model or config.DEEPSEEK_MODEL
        
        if not self.api_key:
            raise ValueError("请设置DEEPSEEK_API_KEY环境变量")
        
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=config.DEEPSEEK_API_URL
        )
        
        # 统计
        self.stats = {
            "calls": 0,
            "tokens": 0,
            "total_time": 0
        }
    
    def infer_source_sink_specs(
        self, 
        apis: List[Dict], 
        cwe_type: str,
        cwe_description: str,
        few_shot_examples: List[Dict] = None,
        batch_size: int = None
    ) -> List[Dict]:
        """
        推断API是源还是汇
        
        Args:
            apis: API列表
            cwe_type: CWE类型 (如 "CWE-89")
            cwe_description: CWE描述
            few_shot_examples: Few-shot示例
            batch_size: 批处理大小
            
        Returns:
            标记后的API列表
        """
        if not apis:
            return []
        
        batch_size = batch_size or config.BATCH_SIZE
        all_results = []
        
        # 打印输入API示例
        logger.info(f"=== 第二阶段: LLM规范推断 ===")
        logger.info(f"CWE类型: {cwe_type}")
        logger.info(f"CWE描述: {cwe_description}")
        logger.info(f"API数量: {len(apis)}")
        logger.info("前5个API示例:")
        for i, api in enumerate(apis[:5]):
            logger.info(f"  {i+1}. {api.get('package')}.{api.get('method')} at {api.get('file')}:{api.get('line')}")
        
        # 分批处理
        for i in range(0, len(apis), batch_size):
            batch = apis[i:i+batch_size]
            logger.info(f"处理批次 {i//batch_size + 1}/{(len(apis)-1)//batch_size + 1} (大小: {len(batch)})")
            
            try:
                batch_results = self._infer_batch(
                    batch, cwe_type, cwe_description, few_shot_examples
                )
                all_results.extend(batch_results)
                
                # 打印本批次结果统计
                sources = [r for r in batch_results if r.get("llm_label") == "source"]
                sinks = [r for r in batch_results if r.get("llm_label") == "sink"]
                logger.info(f"  批次结果: {len(sources)} sources, {len(sinks)} sinks")
                
            except Exception as e:
                logger.error(f"批次处理失败: {e}")
                # 失败时标记为未知
                for api in batch:
                    api["llm_label"] = "unknown"
                    api["llm_confidence"] = 0
                    all_results.append(api)
        
        # 最终统计
        total_sources = [r for r in all_results if r.get("llm_label") == "source"]
        total_sinks = [r for r in all_results if r.get("llm_label") == "sink"]
        logger.info(f"=== 规范推断完成 ===")
        logger.info(f"总API数: {len(all_results)}")
        logger.info(f"Sources: {len(total_sources)}")
        logger.info(f"Sinks: {len(total_sinks)}")
        
        return all_results
    
    def _infer_batch(
        self, 
        apis: List[Dict], 
        cwe_type: str,
        cwe_description: str,
        few_shot_examples: List[Dict] = None
    ) -> List[Dict]:
        """处理单个批次 - 让LLM自己学习判断"""
        
        # 构建API列表文本，只提供原始信息，不预设任何标签
        api_text = ""
        for i, api in enumerate(apis, 1):
            api_text += f"API {i}:\n"
            api_text += f"  包: {api.get('package', 'unknown')}\n"
            if api.get('class'):
                api_text += f"  类: {api['class']}\n"
            api_text += f"  方法: {api.get('method', 'unknown')}()\n"
            api_text += f"  文件: {api.get('file', '')}\n"
            api_text += f"  行号: {api.get('line', 0)}\n"
            if api.get('context'):
                api_text += f"  上下文: {api['context'][:200]}\n"
            api_text += "\n"
        
        # 构建示例文本
        examples_text = ""
        if few_shot_examples:
            examples_text = "参考示例（这些是已知的正确分类，请参考学习）:\n"
            for ex in few_shot_examples:
                examples_text += f"- {ex['package']}"
                if ex.get('class'):
                    examples_text += f".{ex['class']}"
                examples_text += f".{ex['method']}() 是 {ex['type']} "
                examples_text += f"(置信度:{ex['confidence']}) - {ex.get('explanation', '')}\n"
        
        user_prompt = f"""你是一个安全专家。你需要分析以下API列表，判断每个API在{cwe_type}漏洞检测中扮演的角色。

CWE类型: {cwe_type}
CWE描述: {cwe_description}

{examples_text}

请基于你的安全知识，判断每个API是以下哪种角色：
- source: 用户输入入口（如HTTP请求参数、文件上传、用户输入）
- sink: 危险操作点（如文件操作、命令执行、SQL查询）
- propagator: 数据传播函数（如字符串拼接、编码解码）
- none: 无关API

注意：同一个API函数在不同上下文中可能扮演不同角色，请根据具体上下文判断。

以下是需要分析的API列表：

{api_text}

请以JSON格式返回结果，格式为：
{{
    "apis": [
        {{
            "index": {i},
            "package": "包名",
            "class": "类名或null",
            "method": "方法名",
            "type": "source/sink/propagator/none",
            "sink_args": [如果type是sink，指出哪些参数是危险的（索引从0开始）],
            "confidence": 0-100,
            "reasoning": "详细推理过程"
        }}
    ]
}}"""
        
        start_time = time.time()
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一个专业的安全专家，擅长分析代码中的安全漏洞。"},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=config.MAX_TOKENS,
                response_format={"type": "json_object"}
            )
            
            elapsed = time.time() - start_time
            
            # 更新统计
            self.stats["calls"] += 1
            if hasattr(response, 'usage') and response.usage:
                self.stats["tokens"] += response.usage.total_tokens
            self.stats["total_time"] += elapsed
            
            # 解析响应
            content = response.choices[0].message.content
            logger.info(f"LLM原始响应: {content}")
            results = self._parse_response(content, apis)
            
            logger.debug(f"批次处理完成，耗时 {elapsed:.2f}s")
            return results
            
        except Exception as e:
            logger.error(f"DeepSeek API调用失败: {e}")
            raise
    
    def _parse_response(self, content: str, original_apis: List[Dict]) -> List[Dict]:
        """解析LLM响应"""
        try:
            # 清理可能的markdown标记
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            if content.startswith("```"):
                content = content[3:]
            
            data = json.loads(content.strip())
            
            # 提取apis列表
            apis_result = []
            if isinstance(data, dict):
                if "apis" in data:
                    apis_result = data["apis"]
                elif "results" in data:
                    apis_result = data["results"]
                else:
                    # 可能是直接返回列表
                    for key, value in data.items():
                        if isinstance(value, list):
                            apis_result = value
                            break
            
            # 按索引映射结果
            result_by_index = {}
            for item in apis_result:
                if isinstance(item, dict):
                    idx = item.get("index")
                    if idx is not None:
                        result_by_index[idx] = item
            
            # 合并到原始API
            for idx, api in enumerate(original_apis, 1):
                if idx in result_by_index:
                    result_item = result_by_index[idx]
                    api["llm_label"] = result_item.get("type", "none")
                    api["llm_confidence"] = result_item.get("confidence", 50)
                    api["sink_args"] = result_item.get("sink_args", [])
                    api["explanation"] = result_item.get("reasoning", result_item.get("explanation", ""))
                else:
                    # 如果没有对应结果，标记为unknown
                    api["llm_label"] = "unknown"
                    api["llm_confidence"] = 0
                    api["sink_args"] = []
            
            return original_apis
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析失败: {e}")
            logger.debug(f"原始响应: {content[:200]}...")
            
            # 解析失败时标记为未知
            for api in original_apis:
                api["llm_label"] = "unknown"
                api["llm_confidence"] = 0
                api["sink_args"] = []
            return original_apis
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析失败: {e}")
            logger.debug(f"原始响应: {content[:200]}...")
            
            # 解析失败时标记为未知
            for api in original_apis:
                api["llm_label"] = "unknown"
                api["llm_confidence"] = 0
                api["sink_args"] = []
            return original_apis
    
    def validate_vulnerability_path(
        self,
        source: Dict,
        sink: Dict,
        path: List[Dict],
        cwe_type: str,
        code_snippets: Dict[str, str]
    ) -> Dict:
        """
        验证漏洞路径是否真实可利用 - IRIS第四阶段增强版
        
        Args:
            source: 源点信息
            sink: 汇点信息
            path: 污点传播路径
            cwe_type: CWE类型
            code_snippets: 代码片段字典，包含source和sink的上下文代码
            
        Returns:
            {
                "is_vulnerable": True/False,
                "confidence": 0-100,
                "explanation": "详细的推理过程，说明为什么是真实漏洞或误报",
                "attack_scenario": "如果可利用，描述具体攻击方式",
                "recommendation": "具体的修复建议，包括代码示例",
                "sanitizers": ["存在的消毒函数名称列表"],
                "missing_checks": ["缺失的安全检查列表"]
            }
        """
        
        # 构建路径描述
        path_desc = []
        for i, step in enumerate(path[:15]):  # 限制长度
            step_desc = f"步骤{i+1}: {step.get('file', '')}:{step.get('line', '')}"
            if step.get('code'):
                step_desc += f"\n  代码: {step.get('code', '')}"
            if step.get('variable'):
                step_desc += f"\n  变量: {step['variable']}"
            path_desc.append(step_desc)
        
        # 获取上下文代码
        source_context = code_snippets.get('source', '')
        sink_context = code_snippets.get('sink', '')
        
        # 构建增强提示
        user_prompt = f"""CWE类型: {cwe_type}
CWE描述: {CWE_DESCRIPTIONS.get(cwe_type, '')}

【源(Source) - 用户输入入口】:
文件: {source.get('file', '')}
行号: {source.get('line', '')}
代码上下文:{source_context}

【汇(Sink) - 危险函数调用】:
文件: {sink.get('file', '') if sink else source.get('file', '')}
行号: {sink.get('line', '') if sink else source.get('line', '')}
代码上下文:{sink_context}

【完整污点传播路径】:
{chr(10).join(path_desc) if path_desc else "无详细路径信息"}

请分析这个数据流路径，判断是否构成真实可利用的安全漏洞。考虑以下因素：

1. 输入可控性: 攻击者能否完全控制源点的输入值？
2. 消毒函数: 路径中是否存在消毒/过滤函数（如转义、验证、编码）？
3. 上下文限制: 是否有条件判断、类型检查限制了利用？
4. 安全影响: 如果成功利用，会造成什么实际危害？

请以JSON格式返回分析结果：
{{
    "is_vulnerable": true/false,
    "confidence": 0-100,
    "explanation": "详细的推理过程，说明为什么是真实漏洞或误报",
    "attack_scenario": "如果可利用，描述具体攻击方式",
    "recommendation": "具体的修复建议，包括代码示例",
    "sanitizers": ["存在的消毒函数名称列表"],
    "missing_checks": ["缺失的安全检查列表"]
}}"""
        
        # 打印提示词以便调试
        logger.info(f"验证漏洞的提示词:\n{user_prompt}")
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT_PATH_VALIDATION},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=config.MAX_TOKENS,
                response_format={"type": "json_object"}
            )
            
            content = response.choices[0].message.content
            
            # 打印LLM返回的内容
            logger.info(f"LLM返回: {content}")
            
            # 清理响应
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            if content.startswith("```"):
                content = content[3:]
            
            result = json.loads(content)
            
            # 更新统计
            self.stats["calls"] += 1
            if hasattr(response, 'usage') and response.usage:
                self.stats["tokens"] += response.usage.total_tokens
            
            return result
            
        except Exception as e:
            logger.error(f"路径验证失败: {e}")
            return {
                "is_vulnerable": False,
                "confidence": 0,
                "explanation": f"验证过程出错: {e}",
                "attack_scenario": "",
                "recommendation": "",
                "sanitizers": [],
                "missing_checks": []
            }
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return self.stats.copy()
