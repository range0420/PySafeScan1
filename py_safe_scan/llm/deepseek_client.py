"""DeepSeek API客户端 - 增强版支持多轮推理和上下文分析"""

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
        推断API是源还是汇 - IRIS第二阶段
        完全依赖LLM，没有任何硬编码规则
        """
        if not apis:
            return []
        
        batch_size = batch_size or config.BATCH_SIZE
        all_results = []
        
        logger.info(f"=== IRIS第二阶段: LLM规范推断 ===")
        logger.info(f"CWE类型: {cwe_type}")
        logger.info(f"API数量: {len(apis)}")
        
        # 分批处理
        for i in range(0, len(apis), batch_size):
            batch = apis[i:i+batch_size]
            logger.info(f"处理批次 {i//batch_size + 1}/{(len(apis)-1)//batch_size + 1}")
            
            try:
                batch_results = self._infer_batch(
                    batch, cwe_type, cwe_description, few_shot_examples
                )
                all_results.extend(batch_results)
                
                # 统计本批次结果
                sources = [r for r in batch_results if r.get("llm_label") == "source"]
                sinks = [r for r in batch_results if r.get("llm_label") == "sink"]
                logger.info(f"  批次结果: {len(sources)} sources, {len(sinks)} sinks")
                
            except Exception as e:
                logger.error(f"批次处理失败: {e}")
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
    
    def cross_validate_specs(
        self,
        apis: List[Dict],
        cwe_type: str,
        cwe_description: str
    ) -> List[Dict]:
        """
        第二轮：交叉验证低置信度的API
        
        Args:
            apis: 低置信度的API列表
            cwe_type: CWE类型
            cwe_description: CWE描述
            
        Returns:
            重新验证后的API列表
        """
        if not apis:
            return []
        
        logger.info(f"=== 第二轮交叉验证 ===")
        logger.info(f"验证 {len(apis)} 个低置信度API")
        
        # 构建API列表文本
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
                api_text += f"  上下文: {api['context'][:300]}\n"
            api_text += f"  上一轮标签: {api.get('llm_label', 'unknown')}\n"
            api_text += f"  上一轮置信度: {api.get('llm_confidence', 0)}\n"
            api_text += "\n"
        
        user_prompt = f"""你是一个严谨的安全专家。你需要**重新评估**以下API的分类结果。

CWE类型: {cwe_type}
CWE描述: {cwe_description}

这些API在上一轮分类中置信度较低（<80）。请仔细分析每个API的**完整上下文**，判断它是否真的是：
- source: 用户输入入口（如HTTP请求参数、文件上传、用户输入）
- sink: 危险操作点（如文件操作、命令执行、SQL查询）
- none: 无关API

**重要判断准则**：
1. 对于source：函数必须能获取**外部用户输入**（HTTP请求、文件上传、环境变量、命令行参数）
2. 对于sink：函数必须执行**危险操作**（文件写入/读取、命令执行、数据库查询、代码执行）
3. 如果函数只是内部数据处理（字符串操作、数学计算、日志记录），标记为none
4. 上下文比函数名更重要！检查调用上下文是否真的涉及用户输入

以下是需要重新分析的API列表：

{api_text}

请以JSON格式返回，每个API必须包含**详细的推理过程**：
{{
    "apis": [
        {{
            "index": {i},
            "package": "包名",
            "class": "类名或null",
            "method": "方法名",
            "type": "source/sink/none",
            "sink_args": [如果type是sink，指出哪些参数是危险的],
            "confidence": 0-100,
            "reasoning": "详细推理过程，说明为什么是/不是source/sink"
        }}
    ]
}}"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一个严谨的安全专家，擅长分析代码中的安全漏洞。"},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=config.MAX_TOKENS,
                response_format={"type": "json_object"}
            )
            
            self.stats["calls"] += 1
            content = response.choices[0].message.content
            
            # 解析响应
            results = self._parse_response(content, apis)
            
            # 统计重新分类结果
            sources = [r for r in results if r.get("llm_label") == "source"]
            sinks = [r for r in results if r.get("llm_label") == "sink"]
            logger.info(f"第二轮验证结果: {len(sources)} sources, {len(sinks)} sinks")
            
            return results
            
        except Exception as e:
            logger.error(f"交叉验证失败: {e}")
            return apis
    
    def analyze_with_context(
        self,
        apis: List[Dict],
        cwe_type: str
    ) -> List[Dict]:
        """
        第三轮：上下文增强分析
        
        Args:
            apis: 有完整上下文的API列表
            cwe_type: CWE类型
            
        Returns:
            上下文增强分析后的API列表
        """
        if not apis:
            return []
        
        logger.info(f"=== 第三轮上下文增强分析 ===")
        logger.info(f"分析 {len(apis)} 个有完整上下文的API")
        
        enhanced_results = []
        
        for api in apis:
            # 提取更详细的上下文信息
            context = api.get('context', '')
            file_path = api.get('file', '')
            line_num = api.get('line', 0)
            
            # 检查是否在测试文件中
            in_test = 'test' in file_path.lower()
            
            # 检查上下文中的关键模式
            has_request = 'request' in context.lower()
            has_input = 'input' in context.lower()
            has_user = 'user' in context.lower()
            has_sql = any(k in context.lower() for k in ['execute', 'query', 'sql'])
            has_cmd = any(k in context.lower() for k in ['system', 'popen', 'subprocess'])
            has_file = any(k in context.lower() for k in ['open', 'read', 'write', 'path'])
            
            # 构建上下文增强提示
            user_prompt = f"""请分析以下API调用的安全性：

CWE类型: {cwe_type}

【API信息】:
包: {api.get('package', 'unknown')}
类: {api.get('class', 'unknown')}
方法: {api.get('method', 'unknown')}
文件: {file_path}:{line_num}

【完整代码上下文】:{context}

【上下文特征】:
- 在测试文件中: {in_test}
- 涉及HTTP请求: {has_request}
- 涉及用户输入: {has_input}
- 涉及SQL操作: {has_sql}
- 涉及命令执行: {has_cmd}
- 涉及文件操作: {has_file}

基于以上完整上下文，这个API应该被分类为：
- source: 如果它从外部获取用户输入
- sink: 如果它执行危险操作且参数可能被污染
- none: 如果只是内部数据处理

请以JSON格式返回：
{{
    "type": "source/sink/none",
    "confidence": 0-100,
    "reasoning": "基于上下文的详细推理过程",
    "sink_args": [如果type是sink，指出哪些参数危险]
}}"""
            
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "你是一个安全专家，擅长分析代码上下文。"},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0.1,
                    max_tokens=config.MAX_TOKENS,
                    response_format={"type": "json_object"}
                )
                
                self.stats["calls"] += 1
                content = response.choices[0].message.content
                
                # 清理响应
                if content.startswith("```json"):
                    content = content[7:]
                if content.endswith("```"):
                    content = content[:-3]
                if content.startswith("```"):
                    content = content[3:]
                
                result = json.loads(content)
                
                # 更新API信息
                api["llm_label"] = result.get("type", "none")
                api["llm_confidence"] = result.get("confidence", 50)
                api["sink_args"] = result.get("sink_args", [])
                api["explanation"] = result.get("reasoning", "")
                api["context_analyzed"] = True
                
                enhanced_results.append(api)
                
            except Exception as e:
                logger.error(f"上下文分析失败: {e}")
                enhanced_results.append(api)
        
        # 统计
        sources = [r for r in enhanced_results if r.get("llm_label") == "source"]
        sinks = [r for r in enhanced_results if r.get("llm_label") == "sink"]
        logger.info(f"第三轮分析结果: {len(sources)} sources, {len(sinks)} sinks")
        
        return enhanced_results



    
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
            for ex in few_shot_examples[:3]:  # 只取前3个示例
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
- none: 无关API

**注意**：不要过度分类。如果API只是普通的数据处理函数（字符串操作、数学计算、日志记录），请标记为none。

以下是需要分析的API列表：

{api_text}

请以JSON格式返回结果，格式为：
{{
    "apis": [
        {{
            "index": 1,
            "package": "包名",
            "class": "类名或null",
            "method": "方法名",
            "type": "source/sink/none",
            "sink_args": [如果type是sink，指出哪些参数是危险的（索引从0开始）],
            "confidence": 0-100,
            "reasoning": "简要推理过程"
        }}
    ]
}}"""
        
        start_time = time.time()
        
        try:
            logger.info("="*60)
            logger.info("🔍 LLM请求内容:")
            logger.info(f"用户提示词:\n{user_prompt}")
            logger.info("="*60)

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

            logger.info("="*60)
            logger.info("📝 LLM响应内容:")
            logger.info(f"{response.choices[0].message.content}")
            logger.info("="*60)
            
            elapsed = time.time() - start_time
            
            # 更新统计
            self.stats["calls"] += 1
            if hasattr(response, 'usage') and response.usage:
                self.stats["tokens"] += response.usage.total_tokens
            self.stats["total_time"] += elapsed
            
            # 解析响应
            content = response.choices[0].message.content
            logger.debug(f"LLM原始响应: {content[:200]}...")
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
    
    def validate_vulnerability_path_enhanced(
        self,
        source: Dict,
        sink: Dict,
        path: List[Dict],
        cwe_type: str,
        code_snippets: Dict[str, str],
        symbolic_features: Dict[str, Any]
    ) -> Dict:
        """
        增强版路径验证 - 融合符号分析特征
        """
        
        # ============ 最小化的快速规则检查 ============
        # 只保留绝对安全的规则，不针对特定函数
        if cwe_type == "CWE-22":
            sink_context = code_snippets.get('sink', '')
            
            # 类型转换是绝对安全的，因为字符串无法通过int()保持原样
            if 'int(' in sink_context or 'float(' in sink_context:
                return {
                    "is_vulnerable": False,
                    "confidence": 100,
                    "explanation": "用户输入经过了int()/float()类型转换，字符串形式的攻击载荷会被破坏，无法作为路径使用",
                    "attack_scenario": "",
                    "recommendation": "",
                    "sanitizers": ["类型转换"],
                    "missing_checks": [],
                    "validation_reasons": {
                        "type_safe": True
                    }
                }
        
        # ============ 构建路径描述 ============
        path_desc = []
        for i, step in enumerate(path[:10]):
            step_desc = f"步骤{i+1}: {step.get('file', '')}:{step.get('line', '')}"
            if step.get('code'):
                step_desc += f"\n  代码: {step.get('code', '')}"
            path_desc.append(step_desc)
        
        # 获取上下文代码
        source_context = code_snippets.get('source', '')
        sink_context = code_snippets.get('sink', '')
        
        # 构建符号特征描述
        features_desc = "\n".join([
            f"- 路径长度: {symbolic_features.get('path_length', 0)}",
            f"- 跨文件: {'是' if symbolic_features.get('cross_file') else '否'}",
            f"- 经过测试代码: {'是' if symbolic_features.get('passes_test') else '否'}",
            f"- 数据流完整性: {'完整' if symbolic_features.get('flow_complete') else '可能不完整'}"
        ])
        
        # ============ 构建LLM提示词 ============
        # 获取CWE特定提示
        cwe_hints = {
            "CWE-22": """
【CWE-22 路径遍历检测要点】:
- 检查用户输入是否被用于构造文件路径
- 检查是否有路径规范化操作 (如 os.path.normpath, os.path.abspath)
- 检查是否有".."遍历过滤 (如 if '../' in input)
- 检查输入是否被限制在特定目录
- 检查是否使用了安全的API (如 os.path.basename 提取文件名)
- 注意：即使有消毒函数，也要评估消毒是否可以被绕过""",
            
            "CWE-89": """
【CWE-89 SQL注入检测要点】:
- 检查用户输入是否被拼接到SQL查询中
- 检查是否使用了参数化查询或ORM
- 检查是否有转义函数 (如 escape_string)
- 注意：即使是参数化查询，如果拼接了表名/列名也可能危险""",
            
            "CWE-79": """
【CWE-79 XSS检测要点】:
- 检查用户输入是否被直接输出到HTML
- 检查是否有转义函数 (如 escape, html.escape)
- 检查输出上下文 (HTML标签内、属性内、JavaScript内)
- 注意：不同上下文需要不同的转义方式""",
            
            "CWE-94": """
【CWE-94 代码注入检测要点】:
- 检查是否使用了 eval(), exec(), compile() 等函数
- 检查用户输入是否被拼接到代码字符串中
- 检查是否有输入验证或沙箱机制""",
            
            "CWE-78": """
【CWE-78 命令注入检测要点】:
- 检查是否使用了 os.system(), subprocess.Popen() 等
- 检查是否使用了shell=True
- 检查用户输入是否被拼接到命令字符串中
- 检查是否有参数化方式调用命令"""
        }
        
        cwe_hint = cwe_hints.get(cwe_type, "")
        
        user_prompt = f"""你是一个严谨的安全专家，需要严格判断以下数据流路径是否构成**真实可利用**的漏洞。

【CWE类型】: {cwe_type}
【CWE描述】: {CWE_DESCRIPTIONS.get(cwe_type, '')}
{cwe_hint}

【符号分析结果】:
{features_desc}

【源(Source) - 用户输入入口】:
文件: {source.get('file', '')}
行号: {source.get('line', '')}
代码上下文:
{source_context}

【汇(Sink) - 危险函数调用】:
文件: {sink.get('file', '') if sink else source.get('file', '')}
行号: {sink.get('line', '') if sink else source.get('line', '')}
代码上下文:
{sink_context}

【完整污点传播路径】:
{chr(10).join(path_desc) if path_desc else "无详细路径信息"}

【判断标准】:

1. **数据流完整性**: 源点数据是否能实际传递到汇点？路径中是否有断点？

2. **输入可控性**: 攻击者能否完全控制源点的输入值？是否有硬编码前缀/后缀限制？

3. **消毒函数检查**: 路径中是否有消毒/过滤函数？
   - 如果有，评估消毒是否**有效**（能否被绕过）
   - 例如：只过滤一次"../"可能被"....//"绕过
   - 例如：长度限制可能阻止长payload，但不阻止短payload

4. **上下文限制**: 是否有条件判断阻碍利用？
   - 例如：if len(input) > 100: return
   - 例如：if input in whitelist:

5. **类型安全**: 类型转换（int()）会破坏恶意载荷

6. **实际影响**: 成功利用能否造成实际安全危害？

请以JSON格式返回分析结果：

{{
    "is_vulnerable": true/false,
    "confidence": 0-100,
    "explanation": "详细推理过程，解释判断依据",
    "attack_scenario": "如果可利用，描述具体攻击方式",
    "recommendation": "具体的修复建议",
    "sanitizers": ["存在的消毒函数名称列表"],
    "missing_checks": ["缺失的安全检查列表"],
    "validation_reasons": {{
        "data_flow_complete": true/false,
        "input_controllable": true/false,
        "no_sanitization": true/false,
        "no_context_limits": true/false,
        "type_safe": true/false,
        "has_real_impact": true/false
    }}
}}"""
        
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
                "missing_checks": [],
                "validation_reasons": {}
            }
    
    def validate_vulnerability_path(
        self,
        source: Dict,
        sink: Dict,
        path: List[Dict],
        cwe_type: str,
        code_snippets: Dict[str, str]
    ) -> Dict:
        """
        兼容原版接口，调用增强版
        """
        return self.validate_vulnerability_path_enhanced(
            source=source,
            sink=sink,
            path=path,
            cwe_type=cwe_type,
            code_snippets=code_snippets,
            symbolic_features={}
        )
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return self.stats.copy()
