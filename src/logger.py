import datetime
import os 

class Logger:
    def __init__(self, logdir):
        self.logdir = logdir
        os.makedirs(self.logdir, exist_ok=True)
        t = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self._logfile = f"{self.logdir}/pysafescan_{t}.txt"

    def info(self, message):
        t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        s = f"[INFO] [{t}] {message}"
        print(s)
        with open(self._logfile, 'a') as f:
            f.write(s + "\n")

    def error(self, message):
        t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        s = f"[ERROR] [{t}] {message}"
        print(s)
        with open(self._logfile, 'a') as f:
            f.write(s + "\n")
