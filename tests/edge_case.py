import os

def check_logic():
    user = input("Name: ")
    x = user
    y = "safe_value"
    # 这里检测器应该识别出 y 是 CLEAN 的，不应该报错
    os.system("echo " + y) 
    # 这里检测器应该识别出 x 依然是 tainted，必须报错
    os.system("ls " + x)

def multi_step_sql():
    import sqlite3
    db = sqlite3.connect("test.db")
    uid = input("ID: ")
    # 复杂的跨变量传递
    step1 = uid
    step2 = step1
    final_query = f"SELECT * FROM users WHERE id = {step2}"
    db.execute(final_query) # 强大的检测器能追到 uid
