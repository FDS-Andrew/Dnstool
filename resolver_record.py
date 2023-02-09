import dns.resolver

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

        for record_type in resolve_dict:
            try:
                temp_data = dns.resolver.resolve(domain_name, record_type)
                for record_data in temp_data:
                    resolve_dict[record_type].append(record_data.to_text())
            except dns.exception.DNSException:
                resolve_dict[record_type].append("NULL")

        self.resolve_dict = resolve_dict

    def a_record(self):
        return self.resolve_dict["A"]

    def aaaa_record(self):
        return self.resolve_dict["AAAA"]

    def ns_record(self):
        return self.resolve_dict["NS"]

    def mx_record(self):
        return self.resolve_dict["MX"]

    def txt_record(self):
        return self.resolve_dict["TXT"]

    def soa_record(self):
        return self.resolve_dict["SOA"]

