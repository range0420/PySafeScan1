"""
DeepSeek API 客户端 - 专为PySafeScan优化
完整版本
"""
import os
import json
import httpx
from typing import List, Dict, Optional
from openai import OpenAI, APIConnectionError, RateLimitError, APIStatusError

class DeepSeekSecurityAnalyzer:
    """用于分析代码API安全风险的DeepSeek客户端"""

    def __init__(self, api_key: Optional[str] = None, model: str = "deepseek-coder"):
        """
        初始化分析器

        Args:
            api_key: DeepSeek API密钥，默认从环境变量DEEPSEEK_API_KEY读取
            model: 使用的模型，推荐 'deepseek-coder'（代码专用）或 'deepseek-chat'
        """
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        if not self.api_key:
            raise ValueError("""
            ❌ 未设置DeepSeek API密钥。
            请执行以下操作之一：
            1. 设置环境变量: export DEEPSEEK_API_KEY='您的密钥'
            2. 或在项目根目录创建.env文件: echo "DEEPSEEK_API_KEY=您的密钥" > .env
            """)

        # 使用OpenAI SDK（完全兼容DeepSeek API）
        self.client = OpenAI(
            api_key=self.api_key,
            base_url="https://api.deepseek.com/v1",  # DeepSeek API端点
            http_client=httpx.Client(timeout=30.0)
        )
        self.model = model
        self.total_cost = 0.0  # 粗略估算成本（用于比赛展示成本控制）
        print(f"✅ DeepSeek分析器初始化成功，使用模型: {self.model}")

    def analyze_risk_batch(self, api_calls: List[Dict]) -> List[Dict]:
        """
        批量分析API调用的安全风险

        Args:
            api_calls: API调用列表，每个元素包含 'api', 'line', 'file' 等信息

        Returns:
            增强的安全分析结果列表
        """
        if not api_calls:
            return []

        print(f"🤖 开始DeepSeek安全分析，处理 {len(api_calls)} 个API调用...")

        # 1. 构建优化的Prompt（减少token消耗）
        prompt = self._build_security_prompt(api_calls)

        try:
            # 2. 调用DeepSeek API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "你是顶尖的Python代码安全专家，专门分析API调用的安全风险。请严格按JSON格式返回分析结果。"
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                temperature=0.1,  # 低随机性，确保分析结果稳定
                max_tokens=2000,   # 控制输出长度
                response_format={"type": "json_object"}  # 强制JSON格式
            )

            # 3. 估算成本（用于比赛展示）
            # DeepSeek定价: 输入¥1/1M tokens, 输出¥2/1M tokens
            input_tokens = response.usage.prompt_tokens if response.usage else 500
            output_tokens = response.usage.completion_tokens if response.usage else 300
            cost = (input_tokens * 0.000001) + (output_tokens * 0.000002)  # 简化估算
            self.total_cost += cost

            print(f"   📊 本次消耗: {input_tokens}+{output_tokens} tokens ≈ ¥{cost:.4f}")
            print(f"   📈 累计消耗: ¥{self.total_cost:.4f}")

            # 4. 解析响应
            result_text = response.choices[0].message.content
            analysis_result = self._parse_response(result_text)

            # 5. 合并原始API信息和分析结果
            return self._merge_results(api_calls, analysis_result)

        except RateLimitError:
            print("⚠️  API速率限制，请稍后重试或检查配额")
            return self._get_fallback_results(api_calls)
        except APIConnectionError:
            print("🔌  网络连接失败，请检查网络")
            return self._get_fallback_results(api_calls)
        except APIStatusError as e:
            print(f"❌  API错误: {e}")
            return self._get_fallback_results(api_calls)
        except Exception as e:
            print(f"⚠️  未知错误: {type(e).__name__}: {e}")
            return self._get_fallback_results(api_calls)

    def _build_security_prompt(self, api_calls: List[Dict]) -> str:
        """构建安全分析Prompt（优化token使用）"""
        # 提取API签名（不含具体参数值）
        api_details = []
        for i, api in enumerate(api_calls[:15]):  # 限制数量，避免过长
            api_text = api.get('api', '')
            api_details.append(f"{i+1}. {api_text}")

        prompt = f"""请分析以下Python API调用的安全风险，严格按JSON格式返回。

    API调用列表（共{len(api_calls)}个）：
    {chr(10).join(api_details)}

    分析要求（对每个API）：
    1. category: "source"（用户输入点）/ "sink"（危险操作点）/ "propagator"（数据传播）/ "safe"（安全）
    2. risk_level: "high" / "medium" / "low"
    3. vulnerability: "command_injection", "path_traversal", "sql_injection", "deserialization", "xss", "info_leak", "other"
    4. suggestion: 中文修复建议，50字以内

    重要：返回的JSON中，每个"api"字段必须使用上面提供的完整API文本，不要修改！

    返回格式示例：
    {{
      "apis": [
        {{
          "api": "os.system(user_input)",
          "category": "sink",
          "risk_level": "high",
          "vulnerability": "command_injection",
          "suggestion": "使用subprocess.run替代，并对输入参数进行严格验证"
        }}
      ]
    }}

    请开始分析："""
        return prompt

    def _parse_response(self, response_text: str) -> Dict:
        """解析API响应"""
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            print("⚠️  JSON解析失败，使用默认分析")
            # 尝试提取有效部分
            lines = response_text.strip().split('\n')
            for line in lines:
                if line.strip().startswith('{') and line.strip().endswith('}'):
                    try:
                        return json.loads(line)
                    except:
                        continue
            return {"apis": []}

    def _normalize_api_text(self, api_text: str) -> str:
        """规范化API文本用于匹配"""
        if not api_text:
            return ""
        # 移除多余空格
        normalized = ' '.join(api_text.split())
        # 统一参数表示（将具体值替换为...）
        import re
        normalized = re.sub(r'\([^)]*\)', '(...)', normalized)
        return normalized

    def _merge_results(self, api_calls: List[Dict], analysis: Dict) -> List[Dict]:
        """合并原始API信息和分析结果 - 增强匹配版本"""
        results = []
    
        # 创建智能匹配映射
        analysis_map = {}
        for item in analysis.get('apis', []):
            api_key = item.get('api', '')
            if api_key:
                # 规范化API文本用于匹配
                normalized = self._normalize_api_text(api_key)
                analysis_map[normalized] = item

        for i, api_call in enumerate(api_calls):
            api_text = api_call.get('api', '')
            original_api = api_text

            # 尝试多种匹配策略
            analysis_item = {}

            # 1. 完全匹配
            if api_text in analysis_map:
                analysis_item = analysis_map[api_text]

            # 2. 规范化后匹配
            elif self._normalize_api_text(api_text) in analysis_map:
                normalized = self._normalize_api_text(api_text)
                analysis_item = analysis_map[normalized]

            # 3. 提取函数名匹配（如 os.system 匹配 os.system(...)）
            else:
                func_name = api_text.split('(')[0] if '(' in api_text else api_text
                for key in analysis_map:
                    if key.startswith(func_name):
                        analysis_item = analysis_map[key]
                        break

            # 创建增强的结果对象
            enhanced = {
                **api_call,  # 原始信息
                'analysis_id': i + 1,
                'category': analysis_item.get('category', 'unknown'),
                'risk_level': analysis_item.get('risk_level', 'medium'),
                'vulnerability': analysis_item.get('vulnerability', 'other'),
                'suggestion': analysis_item.get('suggestion', '需要人工审查'),
                'ai_analyzed': bool(analysis_item)
            }
            results.append(enhanced)
    
        analyzed_count = sum(1 for r in results if r['ai_analyzed'])
        print(f"   ✅ AI分析完成: {analyzed_count}/{len(results)} 个API获得深度分析")
    
        # 调试信息
        if analyzed_count < len(api_calls) and analysis.get('apis'):
            print(f"   🔍 匹配详情:")
            print(f"       待匹配: {[a.get('api', '')[:30] for a in api_calls[:3]]}")
            print(f"       AI返回: {[a.get('api', '')[:30] for a in analysis['apis']]}")
    
        return results

    def _get_fallback_results(self, api_calls: List[Dict]) -> List[Dict]:
        """API失败时的降级方案"""
        print("   ⚠️  使用启发式规则进行基础分析")
        results = []

        for api in api_calls:
            api_text = api.get('api', '')

            # 简单启发式规则
            if any(kw in api_text.lower() for kw in ['system', 'exec', 'eval', 'pickle', 'yaml.load']):
                risk = 'high'
                category = 'sink'
                vuln = 'command_injection' if 'system' in api_text or 'exec' in api_text else 'deserialization'
            elif 'open' in api_text:
                risk = 'medium'
                category = 'sink'
                vuln = 'path_traversal'
            elif 'input' in api_text or 'args' in api_text:
                risk = 'medium'
                category = 'source'
                vuln = 'other'
            else:
                risk = 'low'
                category = 'propagator'
                vuln = 'other'

            results.append({
                **api,
                'category': category,
                'risk_level': risk,
                'vulnerability': vuln,
                'suggestion': 'API调用失败，此为启发式分析结果，建议人工审查',
                'ai_analyzed': False
            })

        return results

    def quick_test(self):
        """快速测试函数"""
        print("🧪 执行DeepSeek客户端快速测试...")

        test_apis = [
            {"api": "os.system(user_input)", "line": 10, "file": "test.py"},
            {"api": "open(filename, 'r')", "line": 15, "file": "test.py"},
            {"api": "eval(expression)", "line": 20, "file": "test.py"}
        ]

        results = self.analyze_risk_batch(test_apis)

        print("\n测试结果预览:")
        for result in results:
            print(f"  [{result['risk_level'].upper()}] {result['api']}")
            print(f"     分类: {result['category']}, 漏洞: {result['vulnerability']}")
            print(f"     建议: {result['suggestion'][:50]}...")

        return results


def main():
    """主测试函数"""
    print("=" * 60)
    print("DeepSeek Security Analyzer - 测试套件")
    print("=" * 60)
    
    try:
        # 从环境变量读取API密钥
        analyzer = DeepSeekSecurityAnalyzer()
        analyzer.quick_test()

        print(f"\n✅ 测试完成！累计估算成本: ¥{analyzer.total_cost:.4f}")

    except ValueError as e:
        print(f"❌ 初始化失败: {e}")
        print("\n💡 解决方案:")
        print("1. 创建.env文件: echo 'DEEPSEEK_API_KEY=您的密钥' > .env")
        print("2. 或在shell中: export DEEPSEEK_API_KEY='您的密钥'")
        print("3. 然后重新运行测试")


if __name__ == "__main__":
    main()
