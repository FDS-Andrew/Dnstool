from pythonping import ping

class Check:
    def __init__(self, domain_name):
        self.domain_name = domain_name

    def validity(self):
        try:
            ping(self.domain_name, count=3, size=1)
            return True
        except RuntimeError:
            return False

