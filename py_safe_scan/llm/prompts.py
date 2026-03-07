"""LLM提示词模板 - 完整版支持所有CWE类型"""

# ============ 系统提示词 - 规范推断 ============
SYSTEM_PROMPT_SPEC_INFERENCE = """你是一个精通Python安全的专家。你需要分析给定的API列表，判断每个API在安全漏洞检测中扮演的角色。

请基于你的知识判断，不需要外部文档。考虑以下Python标准库和常见框架的安全相关API：

文件操作相关（可能成为SINK）：
- open, codecs.open, os.open, pathlib.Path.read_text/write_text
- 任何读取、写入、打开文件的函数

命令执行相关（SINK）：
- os.system, os.popen, subprocess.run/call/Popen
- eval, exec, compile

Web框架相关（可能成为SOURCE）：
- request对象的方法（get, form, cookies, args, json）
- 任何从HTTP请求获取数据的函数

数据解码/编码相关（可能成为PROPAGATOR）：
- urllib.parse.unquote/unquote_plus, base64解码
- json.loads, pickle.loads（如果处理不可信数据则是SINK）

数据库相关（SQL注入SINK）：
- execute, executemany, cursor.execute
- 任何执行SQL语句的函数

XML处理相关（XXE/XPath注入SINK）：
- parse, parseString, ElementTree.parse, etree.parse
- xpath, find, findall（如果使用用户输入）

序列化相关（反序列化SINK）：
- pickle.loads, pickle.load, yaml.load, json.loads

请按以下JSON格式返回：
{
    "apis": [
        {
            "package": "包名",
            "class": "类名或null",
            "method": "方法名",
            "type": "source/sink/propagator/none",
            "sink_args": [参数索引列表],
            "confidence": 0-100,
            "reasoning": "简要推理"
        }
    ]
}"""

# ============ 系统提示词 - 路径验证 ============
SYSTEM_PROMPT_PATH_VALIDATION = """你是一个安全专家。你需要分析一个被静态分析工具检测到的潜在漏洞路径，判断它是否真实可利用。

请仔细分析提供的源点(Source)、汇点(Sink)和完整的污点传播路径。考虑以下因素：

1. 输入可控性：攻击者能否完全控制源点的输入值？是否有验证或限制？
2. 消毒函数：路径中是否存在消毒/过滤函数（如转义、验证、编码、类型检查）？
3. 上下文限制：是否有条件判断、类型检查、异常处理限制了利用？
4. 安全影响：如果成功利用，会造成什么实际危害？
5. 路径完整性：数据是否真的从源点流到了汇点？中间是否有断点？

请以JSON格式返回分析结果：
{
    "is_vulnerable": true/false,
    "confidence": 0-100,
    "explanation": "详细的推理过程，说明为什么是真实漏洞或误报",
    "attack_scenario": "如果可利用，描述具体攻击方式",
    "recommendation": "具体的修复建议，包括代码示例",
    "sanitizers": ["存在的消毒函数名称列表"],
    "missing_checks": ["缺失的安全检查列表"]
}"""

# ============ 系统提示词 - 漏洞解释 ============
SYSTEM_PROMPT_VULNERABILITY_EXPLANATION = """你是一个安全专家。请用通俗易懂的语言解释这个安全漏洞，包括：
1. 漏洞是什么
2. 为什么危险
3. 如何修复

请以JSON格式回答：
{
    "summary": "一句话总结",
    "description": "详细解释",
    "impact": "可能造成的影响",
    "recommendation": "修复建议",
    "example_fix": "示例修复代码（如果有）"
}"""

# ============ 系统提示词 - 公开函数参数分析 ============
SYSTEM_PROMPT_FUNCTION_ANALYSIS = """你是一个安全专家。你需要分析给定的公开函数及其文档，判断这个函数的参数是否可能成为污点分析的源点(Source)。

考虑以下因素：
1. 函数是否是API端点（如Flask路由）？
2. 函数文档是否说明参数来自用户输入？
3. 函数名是否暗示参数来自外部（如get_user_input, handle_request）？
4. 项目文档（README）是否提到这个函数供外部调用？

请以JSON格式返回：
{
    "functions": [
        {
            "name": "函数名",
            "module": "模块名",
            "parameters": [
                {
                    "name": "参数名",
                    "is_source": true/false,
                    "confidence": 0-100,
                    "reasoning": "推理过程"
                }
            ]
        }
    ]
}"""

# ============ 系统提示词 - API误用分析 ============
SYSTEM_PROMPT_API_MISUSE = """你是一个安全专家。你需要分析一个API调用是否存在安全风险。

考虑以下因素：
1. 参数是否可能被用户控制？
2. 是否有安全的使用方式（如参数化查询vs字符串拼接）？
3. 文档中是否有安全警告？
4. 上下文是否有消毒措施？

请以JSON格式返回：
{
    "is_unsafe": true/false,
    "confidence": 0-100,
    "explanation": "解释为什么不安全或安全",
    "safe_alternative": "安全的使用方式"
}"""

# 为了向后兼容
SYSTEM_PROMPTS = {
    "spec_inference": SYSTEM_PROMPT_SPEC_INFERENCE,
    "path_validation": SYSTEM_PROMPT_PATH_VALIDATION,
    "vulnerability_explanation": SYSTEM_PROMPT_VULNERABILITY_EXPLANATION,
    "function_analysis": SYSTEM_PROMPT_FUNCTION_ANALYSIS,
    "api_misuse": SYSTEM_PROMPT_API_MISUSE
}

# ============ 完整的CWE描述 ============
CWE_DESCRIPTIONS = {
    # 注入类
    "CWE-22": "路径遍历: 当用户输入用于构造文件路径，可能导致访问敏感文件",
    "CWE-78": "命令注入: 当用户输入被拼接到系统命令中，可能导致任意命令执行",
    "CWE-79": "跨站脚本(XSS): 当用户输入被直接输出到网页，可能导致恶意脚本执行",
    "CWE-89": "SQL注入: 当用户输入拼接到SQL查询中，可能导致数据库被恶意操作",
    "CWE-90": "LDAP注入: 当用户输入拼接到LDAP查询中，可能导致未授权访问",
    "CWE-94": "代码注入: 当用户输入被传递给eval()、exec()等函数，可能导致任意代码执行",
    "CWE-117": "日志注入: 未经验证的输入写入日志，可能导致日志伪造",
    "CWE-643": "XPath注入: 用户输入拼接到XPath查询中，可能导致信息泄露",
    "CWE-918": "SSRF: 服务端请求伪造，可能导致内部网络探测",
    
    # 加密与随机数
    "CWE-326": "弱加密密钥: 使用过短的加密密钥",
    "CWE-327": "加密问题: 使用有缺陷的加密算法或模式",
    "CWE-328": "哈希问题: 使用有缺陷的哈希算法",
    "CWE-330": "弱随机数: 使用可预测的随机数生成器",
    
    # 配置错误
    "CWE-215": "调试信息泄露: 在生产环境中启用了调试模式",
    "CWE-693": "安全配置错误: 应用安全配置不当",
    "CWE-942": "CORS配置不当: 跨域资源共享配置过于宽松",
    
    # XXE
    "CWE-611": "XXE注入: XML外部实体注入，可能导致文件读取或SSRF",
    
    # 重定向
    "CWE-601": "URL重定向: 用户输入控制重定向URL，可能导致网络钓鱼",
    
    # 硬编码凭证
    "CWE-321": "硬编码密钥: 代码中包含硬编码的加密密钥",
    "CWE-798": "硬编码凭证: 代码中包含硬编码的密码或凭证",
    "CWE-345": "不充分的验证: 对JWT等令牌的验证不足",
    
    # 信息泄露
    "CWE-209": "错误信息泄露: 堆栈跟踪暴露给用户",
    "CWE-312": "敏感数据明文存储: 密码等敏感信息以明文存储",
    "CWE-532": "敏感数据日志记录: 敏感信息被写入日志",
    
    # 其他
    "CWE-80": "模板注入: 模板中未转义用户输入",
    "CWE-93": "SMTP注入: 未验证的输入影响邮件头",
    "CWE-502": "不安全反序列化: 从不可信源反序列化数据",
    "CWE-614": "安全Cookie: 未设置安全标志的Cookie",
    "CWE-501": "信任边界: 跨越信任边界的违规行为",
}

# ============ 完整的few-shot示例 ============
FEW_SHOT_EXAMPLES = {
    # 路径遍历
    "CWE-22": [
        {
            "package": "flask",
            "class": "request",
            "method": "args.get",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "从HTTP查询参数获取用户输入，可能包含文件路径"
        },
        {
            "package": "flask",
            "class": "request",
            "method": "cookies.get",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "从HTTP Cookie获取用户输入，可能包含文件路径"
        },
        {
            "package": "builtins",
            "class": None,
            "method": "open",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "文件打开函数，路径参数可能被污染"
        },
        {
            "package": "os",
            "class": None,
            "method": "listdir",
            "type": "sink",
            "sink_args": [0],
            "confidence": 90,
            "explanation": "列出目录内容，路径参数可能被污染"
        }
    ],
    
    # 命令注入
    "CWE-78": [
        {
            "package": "flask",
            "class": "request",
            "method": "args.get",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "从HTTP查询参数获取用户输入，可能包含命令"
        },
        {
            "package": "flask",
            "class": "request",
            "method": "form.get",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "从HTTP表单获取用户输入，可能包含命令"
        },
        {
            "package": "os",
            "class": None,
            "method": "system",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "执行系统命令，参数直接传递给shell"
        },
        {
            "package": "os",
            "class": None,
            "method": "popen",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "执行系统命令并打开管道"
        },
        {
            "package": "subprocess",
            "class": None,
            "method": "Popen",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "执行子进程，如果使用shell=True则危险"
        },
        {
            "package": "subprocess",
            "class": None,
            "method": "run",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "执行子进程，如果使用shell=True则危险"
        }
    ],
    
    # XSS
    "CWE-79": [
        {
            "package": "flask",
            "class": "request",
            "method": "args.get",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "从HTTP查询参数获取用户输入，可能包含JavaScript代码"
        },
        {
            "package": "flask",
            "class": None,
            "method": "render_template_string",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "渲染模板字符串，如果包含未转义的用户输入则危险"
        },
        {
            "package": "flask",
            "class": None,
            "method": "make_response",
            "type": "sink",
            "sink_args": [0],
            "confidence": 80,
            "explanation": "创建响应，如果内容类型为HTML且包含用户输入则危险"
        }
    ],
    
    # SQL注入
    "CWE-89": [
        {
            "package": "flask",
            "class": "request",
            "method": "args.get",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "从HTTP查询参数获取用户输入，可能包含SQL语句"
        },
        {
            "package": "flask",
            "class": "request",
            "method": "form.get",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "从HTTP表单获取用户输入，可能包含SQL语句"
        },
        {
            "package": "sqlite3",
            "class": "Cursor",
            "method": "execute",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "执行SQL语句，如果第一个参数是字符串拼接则危险"
        },
        {
            "package": "sqlite3",
            "class": "Cursor",
            "method": "executemany",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "执行多条SQL语句，如果第一个参数是字符串拼接则危险"
        },
        {
            "package": "MySQLdb",
            "class": "Cursor",
            "method": "execute",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "执行SQL语句，如果第一个参数是字符串拼接则危险"
        }
    ],
    
    # LDAP注入
    "CWE-90": [
        {
            "package": "flask",
            "class": "request",
            "method": "form.get",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "从HTTP表单获取用户输入，可能包含LDAP过滤器"
        },
        {
            "package": "ldap3",
            "class": "Connection",
            "method": "search",
            "type": "sink",
            "sink_args": [1],
            "confidence": 100,
            "explanation": "LDAP搜索，搜索过滤器参数可能被污染"
        }
    ],
    
    # 代码注入
    "CWE-94": [
        {
            "package": "flask",
            "class": "request",
            "method": "data",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "获取原始请求数据，可能包含代码"
        },
        {
            "package": "builtins",
            "class": None,
            "method": "eval",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "执行Python表达式，参数可能包含恶意代码"
        },
        {
            "package": "builtins",
            "class": None,
            "method": "exec",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "执行Python代码，参数可能包含恶意代码"
        },
        {
            "package": "builtins",
            "class": None,
            "method": "compile",
            "type": "sink",
            "sink_args": [0],
            "confidence": 90,
            "explanation": "编译Python代码，源参数可能被污染"
        }
    ],
    
    # XXE注入
    "CWE-611": [
        {
            "package": "flask",
            "class": "request",
            "method": "data",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "获取原始请求数据，可能包含XML"
        },
        {
            "package": "xml.etree.ElementTree",
            "class": None,
            "method": "parse",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "解析XML，如果不禁用外部实体则危险"
        },
        {
            "package": "xml.etree.ElementTree",
            "class": None,
            "method": "fromstring",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "从字符串解析XML，如果不禁用外部实体则危险"
        },
        {
            "package": "lxml",
            "class": "etree",
            "method": "parse",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "解析XML，如果不禁用外部实体则危险"
        }
    ],
    
    # XPath注入
    "CWE-643": [
        {
            "package": "flask",
            "class": "request",
            "method": "args.get",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "从HTTP查询参数获取用户输入，可能包含XPath表达式"
        },
        {
            "package": "lxml",
            "class": "etree",
            "method": "xpath",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "执行XPath查询，表达式参数可能被污染"
        }
    ],
    
    # 不安全反序列化
    "CWE-502": [
        {
            "package": "flask",
            "class": "request",
            "method": "data",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "获取原始请求数据，可能包含序列化对象"
        },
        {
            "package": "pickle",
            "class": None,
            "method": "loads",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "反序列化pickle数据，可能执行任意代码"
        },
        {
            "package": "pickle",
            "class": None,
            "method": "load",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "从文件反序列化pickle数据，可能执行任意代码"
        },
        {
            "package": "yaml",
            "class": None,
            "method": "load",
            "type": "sink",
            "sink_args": [0],
            "confidence": 90,
            "explanation": "加载YAML，如果使用不安全的load则危险"
        }
    ],
    
    # SSRF
    "CWE-918": [
        {
            "package": "flask",
            "class": "request",
            "method": "args.get",
            "type": "source",
            "sink_args": [],
            "confidence": 100,
            "explanation": "从HTTP查询参数获取用户输入，可能包含URL"
        },
        {
            "package": "requests",
            "class": None,
            "method": "get",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "发送HTTP GET请求，URL参数可能被污染"
        },
        {
            "package": "requests",
            "class": None,
            "method": "post",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "发送HTTP POST请求，URL参数可能被污染"
        },
        {
            "package": "urllib",
            "class": "request",
            "method": "urlopen",
            "type": "sink",
            "sink_args": [0],
            "confidence": 100,
            "explanation": "打开URL，URL参数可能被污染"
        }
    ]
}

# 通用示例（当没有特定CWE示例时使用）
GENERIC_EXAMPLES = [
    {
        "package": "flask",
        "class": "request",
        "method": "args.get",
        "type": "source",
        "confidence": 100,
        "explanation": "从HTTP请求获取用户输入，是典型的source"
    },
    {
        "package": "flask",
        "class": "request",
        "method": "form.get", 
        "type": "source",
        "confidence": 100,
        "explanation": "从HTTP表单获取用户输入，是典型的source"
    },
    {
        "package": "flask",
        "class": "request",
        "method": "cookies.get",
        "type": "source",
        "confidence": 100,
        "explanation": "从HTTP Cookie获取用户输入，是典型的source"
    },
    {
        "package": "flask",
        "class": "request",
        "method": "headers.get",
        "type": "source",
        "confidence": 100,
        "explanation": "从HTTP头获取用户输入，是典型的source"
    }
]
