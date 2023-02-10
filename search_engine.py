import dns.resolver
import whois

class Resolver:
    def __init__(self, domain_name):
        resolve_dict = {
            "A":    [],
            "AAAA": [],
            "NS":   [],
            "MX":   [],
            "TXT":  [],
            "SOA":  [],
        }
        
        self.domain_name = domain_name
        self.resolve_dict = resolve_dict

    def extractor(self, record_type) -> list:
        try:
            temp_data = dns.resolver.resolve(self.domain_name, record_type)
            for record_data in temp_data:
                self.resolve_dict[record_type].append(record_data.to_text())
            return  self.resolve_dict[record_type]

        except dns.exception.DNSException:
            return  [None]

    def get_a_record(self) -> list:
        return self.extractor("A")

    def get_aaaa_record(self) -> list:
        return self.extractor("AAAA")

    def get_ns_record(self) -> list:
        return self.extractor("NS")

    def get_mx_record(self) -> list:
        return self.extractor("MX")

    def get_txt_record(self) -> list:
        return self.extractor("TXT")

    def get_soa_record(self) -> list:
        return self.extractor("SOA")


class Whois:
    def __init__(self, domain_name):
        self.whois_record = whois.whois(domain_name)

    def get_registrar(self) -> str:
        return self.whois_record.registrar

    def get_expiration_date(self) -> str:
        return self.whois_record.expiration_date

    def get_name_servers(self) -> str:
        return self.whois_record.name_servers
