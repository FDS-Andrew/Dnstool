import dns.resolver

class Check:
    def __init__(self, domain_name):
        proceed = True

        try:
            dns.resolver.resolve(domain_name, "A")
        except dns.exception.DNSException:
            proceed = False

        self.proceed = proceed

    def validity(self):
        if self.proceed:
            return True
