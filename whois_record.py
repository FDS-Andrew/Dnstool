import whois

class Whois_Records:
    def __init__(self, domain_name):
        self.record = whois.whois(domain_name)

    def get_registrar(self):
        return self.record.registrar

    def get_expiration_date(self):
        return self.record.expiration_date

    def get_name_servers(self):
        return self.record.name_servers
