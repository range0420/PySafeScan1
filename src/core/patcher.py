import os
import re

def apply_fix(file_path, line_num, old_code, new_code, full_context=None, is_block_fix=False):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 如果是块修复
    if is_block_fix and full_context:
        # 1. 清理 full_context 中的 AI 注入标签 (比如 # Local Context Body 等)
        # 我们只取函数定义开始到结束的部分
        lines_context = [l for l in full_context.splitlines() if not l.startswith('#')]
        actual_context = "\n".join(lines_context).strip()
        
        # 2. 尝试全文替换
        if actual_context in content:
            new_content = content.replace(actual_context, new_code.strip())
        else:
            # 3. 备选方案：如果 full_context 匹配失败，说明 context 里的描述太多了
            # 我们直接以 line_num 为中心，向上向下扫描函数块进行替换
            # 或者简单点：既然是重构，我们直接把 old_code 这一行及其紧邻的上下文替换
            lines = content.splitlines()
            # 这里的逻辑是：既然要重构，我们要找的是从这一行往上数，直到看到 def 的位置
            start_line = line_num - 1
            while start_line > 0 and not lines[start_line].strip().startswith('def '):
                start_line -= 1
            
            # 找到函数结束（简单的启发式：直到下一个 def 或文件末尾）
            end_line = line_num
            while end_line < len(lines) and not lines[end_line].strip().startswith('def '):
                end_line += 1
            
            # 替换整个切片
            lines[start_line:end_line] = [new_code]
            new_content = "\n".join(lines)
    else:
        # 单行替换
        lines = content.splitlines()
        lines[line_num - 1] = new_code
        new_content = "\n".join(lines)

    target_path = f"{file_path}.fixed"
    with open(target_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    return target_path


def apply_fix_in_memory(current_content, line_num, full_context, new_code, is_block_fix=False):
    """
    内存级修复：精准定位函数范围并执行整体置换（支持倒序修复）。
    """
    # 1. 定义并提取 clean_fix（解决 NameError）
    # 提取 new_code 中的 import 语句并准备置顶
    import_lines = [l.strip() for l in new_code.splitlines() if l.strip().startswith(('import ', 'from '))]
    # 过滤掉 import 语句，得到纯粹的修复代码体
    clean_fix = "\n".join([l for l in new_code.splitlines() if not l.strip().startswith(('import ', 'from '))]).strip()

    # 2. 执行 Import 漂移
    if import_lines:
        for imp in import_lines:
            if imp not in current_content:
                current_content = imp + "\n" + current_content

    lines = current_content.splitlines()

    # 3. 如果是块修复，执行“范围切除”
    if is_block_fix:
        # A. 向上寻找：必须摸到装饰器 (@) 或函数定义 (def)
        start_idx = line_num - 1
        while start_idx > 0:
            line_content = lines[start_idx].strip()
            # 向上穿透空行和注释，直到发现函数特征
            if line_content.startswith(('def ', '@')):
                # 发现函数特征后，继续向上检查是否有连续的装饰器
                if start_idx > 0 and lines[start_idx-1].strip().startswith('@'):
                    start_idx -= 1
                    continue
                break
            start_idx -= 1
        
        # B. 向下寻找：直到遇到下一个函数起点或逻辑终点
        end_idx = line_num - 1
        while end_idx < len(lines) - 1:
            next_l = lines[end_idx + 1].strip()
            if next_l.startswith(('@', 'def ')) or next_l.startswith('if __name__'):
                break
            end_idx += 1

        # C. 强制替换整个范围，确保旧代码不留残余
        lines[start_idx : end_idx + 1] = [clean_fix]
        return "\n".join(lines)

    # 4. 单行修复保底
    if 0 < line_num <= len(lines):
        lines[line_num - 1] = clean_fix
    
    return "\n".join(lines)
