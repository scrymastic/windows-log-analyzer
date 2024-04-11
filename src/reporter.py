

class Reporter:
    def __init__(self, name):
        self.name = name

    def report(self, message):
        print(f"{self.name}: {message}")