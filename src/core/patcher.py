import re

_fixed_scopes = set()

def apply_fix_in_memory(current_content, line_num, full_context, new_code, is_block_fix=False, target_func_name=None):
    if not current_content or not new_code:
        return current_content
    
    lines = current_content.splitlines()
    scope_id = str(target_func_name)
    if scope_id in _fixed_scopes and scope_id != "Global":
        return current_content

    # 1. 定位函数
    func_start = -1
    if target_func_name and target_func_name != "Global":
        pattern = re.compile(fr"def\s+{target_func_name}\s*\(")
        for i, line in enumerate(lines):
            if pattern.search(line):
                func_start = i
                break
    
    if func_start == -1:
        cursor = min(line_num - 1, len(lines) - 1)
        while cursor >= 0:
            if lines[cursor].lstrip().startswith('def '):
                func_start = cursor
                break
            cursor -= 1
    if func_start == -1: return current_content

    # 2. 装饰器处理
    while func_start > 0 and lines[func_start-1].strip().startswith('@'):
        func_start -= 1

    # 3. 获取目标基准缩进
    def_line_idx = func_start
    while def_line_idx < len(lines) and not lines[def_line_idx].lstrip().startswith('def '):
        def_line_idx += 1
    
    # 目标函数定义本身的缩进 (Global 是 0, Class 方法是 4)
    base_indent_count = len(lines[def_line_idx]) - len(lines[def_line_idx].lstrip())
    
    # 4. 确定函数结束位置
    header_end = def_line_idx
    while header_end < len(lines) and ":" not in lines[header_end]:
        header_end += 1
    func_end = header_end
    for i in range(header_end + 1, len(lines)):
        if lines[i].strip():
            curr_indent = len(lines[i]) - len(lines[i].lstrip())
            if curr_indent <= base_indent_count and not lines[i].strip().startswith((')', ']', '}')):
                break
        func_end = i

    # 5. 【核心手术】强制缩进重排列
    raw_fix_lines = new_code.splitlines()
    blacklist = ["def ", "class ", "import ", "from ", "```", "@"]
    # 仅保留有效逻辑行
    clean_lines = [l for l in raw_fix_lines if l.strip() and not any(l.strip().startswith(b) for b in blacklist)]
    if not clean_lines: return current_content

    # 第一步：找到 AI 代码块中最浅的缩进量
    ai_min_indent = min(len(l) - len(l.lstrip()) for l in clean_lines)
    
    final_body_lines = []
    # 函数体内标准的起始位置应该是 base + 4
    target_start_indent = base_indent_count + 4

    for line in clean_lines:
        # 1. 先把 AI 的缩进剥离，让它彻底左对齐 (归零)
        stripped_line = line[ai_min_indent:] if len(line) >= ai_min_indent else line.lstrip()
        # 2. 加上我们计算出的绝对正确缩进
        final_body_lines.append((" " * target_start_indent) + stripped_line)

    # 6. 原子替换
    header_part = "\n".join(lines[func_start : header_end + 1])
    indented_body = "\n".join(final_body_lines)
    lines[func_start : func_end + 1] = [header_part + "\n" + indented_body]
    
    if scope_id != "Global": _fixed_scopes.add(scope_id)
    return "\n".join(lines)
