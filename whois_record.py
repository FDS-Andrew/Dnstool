import whois

class Whois_Records:
    def __init__(self, domain_name):
        self.record = whois.whois(domain_name)

    def get_registrar(self) -> str:
        return self.record.registrar

    def get_expiration_date(self) -> str:
        return self.record.expiration_date

    def get_name_servers(self) -> str:
        return self.record.name_servers
