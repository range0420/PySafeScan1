import os
import subprocess

def test_param_awareness():
    cmd = input()
    # 场景 A: shell=False，不应该报错（现代引擎的标志）
    subprocess.run(["ls", cmd], shell=False) 
    
    # 场景 B: shell=True，必须报错
    subprocess.run(f"ls {cmd}", shell=True)

def test_implicit_sink():
    data = input()
    # 这种隐式执行非常危险
    eval(data)
