import datetime

class MyLogger:
    def __init__(self, log_file):
        self.log_file = log_file
        with open(self.log_file, 'a') as f:
            f.write(f"\n--- Session Started: {datetime.datetime.now()} ---\n")

    def log(self, message):
        print(message)
        with open(self.log_file, 'a') as f:
            f.write(f"{message}\n")
